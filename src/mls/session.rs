//! The per-connection MLS session facade (REQ-023 + the chat-session wiring).
//!
//! One agent connection = one channel = one MLS group (ADR-005). The chat
//! receive loop owns one `MlsSession` and routes every inbound payload
//! through [`MlsSession::handle_frame`] before the responder sees it, and
//! every outbound payload through [`MlsSession::encrypt_outbound`] before
//! signing — so in a pinned-encrypted channel no message content ever leaves
//! as plaintext (REQ-005, NFR-002).
//!
//! **The encryption-mode pin (REQ-023)** is derived from the admission path
//! — presenting a `:cap`/invite token IS joining a private (⇒ encrypted)
//! channel — or from explicit operator intent, never from the unsigned hub
//! `roomcfg :enc` bit, and never by first-observation TOFU of that bit. A
//! `roomcfg :enc false` on a pinned channel is a downgrade attack: the
//! session fails closed (refuses to send) and surfaces the conflict. The pin
//! persists across restarts, so a returning daemon stays pinned even when no
//! cap is re-presented.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use cbcl_core::sexpr::{Atom, SExpr};
use openmls::group::GroupId;
use openmls::prelude::MlsGroup;
use rand::Rng as _;

use super::group::{
    GenesisAssertion, GenesisTrust, add_member, create_group, group_genesis_creator, is_owner,
    join_by_grant, join_from_welcome, member_bindings, verify_add_target,
};
use super::keypackages::{
    ConsumedLedger, ONE_TIME_POOL_TARGET, build_last_resort, build_one_time,
    validate_key_package_bytes,
};
use super::pins::{PinStore, idkey_signing_bytes};
use super::provider::DurableProvider;
use super::removal::{RemovalEvidence, remove_member};
use super::safety::{SafetyNumbers, group_safety_numbers};
use super::validation::{ForkSignal, Inbound, encrypt_message, enforce_sender, process_inbound};
use super::{MlsError, MlsIdentity};
use openmls_traits::OpenMlsProvider;

use crate::chat_frame::FrameSigner;
use crate::identity::ChatIdentity;

const META_VERSION: u32 = 1;

/// Durable per-(agent, room) session metadata: the mode pin, the group id,
/// and the genesis assertion — everything needed to resume after a restart
/// (REQ-009, REQ-023 pin persistence).
#[derive(serde::Serialize, serde::Deserialize)]
struct SessionMeta {
    version: u32,
    room: String,
    enc_pinned: bool,
    group_id_b64: Option<String>,
    genesis: Option<GenesisAssertion>,
    /// True when the group was joined as first-contact TOFU and the operator
    /// has NOT yet confirmed the REQ-021 safety number out-of-band. Persisted
    /// so a daemon restart does NOT silently promote an unconfirmed (possibly
    /// hub-fabricated) group to authoritative — the safety-number control
    /// must survive HP-3 (REQ-016/ADR-006).
    #[serde(default)]
    tofu_pending: bool,
    /// SPEC-024 per-room protocol version (ADR-034): 0/absent = legacy SPEC-013, 1 = mls-ds/v1.
    /// On a v1 room, owner-removal is deterministically rejected (H7) and the pull loop is active.
    #[serde(default)]
    protocol_version: u8,
    /// SPEC-061 REQ-008: the pairing admission grant this agent holds, as JSON.
    ///
    /// Durable because the whole point of it is an admission that does not need
    /// anybody present: the member that signed it may be gone by the time we can
    /// use it, and a grant kept only in memory would be lost on exactly the
    /// restart this is meant to survive. It is not a secret — it authorises one
    /// key, ours — so it sits beside the genesis rather than with key material.
    #[serde(default)]
    pair_grant: Option<String>,
    /// REQ-026(a)(ii): the highest resync nonce honoured per requester.
    ///
    /// DURABLE, and that is the whole point of it. Held only in memory, the floor
    /// resets to empty on every restart — so a hub that captured one valid resync
    /// can replay it after any restart of ours and churn a member that is
    /// perfectly healthy. A replay window that reopens on a restart is not a
    /// replay defence; it is one that happens to be closed while nothing has
    /// gone wrong.
    #[serde(default)]
    resync_nonces: std::collections::HashMap<String, u64>,
    /// REQ-026(e): honoured resyncs per requester, as `(window index, count)`.
    ///
    /// Durable for the same reason: a budget that empties on restart bounds
    /// nothing an attacker who can cause restarts cares about, and restarts are
    /// ordinary — a deploy, a crash, a laptop lid.
    #[serde(default)]
    resync_honoured: std::collections::HashMap<String, (u64, u32)>,
}

/// What an inbound frame turned out to be.
#[derive(Debug)]
pub enum SessionEvent {
    /// Not an MLS frame — let the existing plaintext path handle it (only
    /// reachable when the channel is not pinned encrypted, or for control
    /// frames like `presence`).
    NotMls,
    /// A decrypted application payload, sender-authenticated (REQ-018
    /// already enforced against the inner `:from`).
    Plaintext { text: String, sender: String },
    /// An MLS handshake/control frame was consumed; optionally frames to
    /// send back (keyget after presence, commit+welcome after keypkg, …).
    Handled { outbound: Vec<String> },
    /// The frame was dropped (undecryptable / failed validation); the
    /// reason is surfaced for logs and the fork flag for REQ-006/REQ-021.
    Dropped { reason: String, probable_fork: bool },
    /// SPEC-013 REQ-025: the drop crossed the fork threshold, the forked group
    /// has been discarded, and `outbound` is the signed re-admission request.
    ///
    /// Its own variant rather than a flag on [`Self::Dropped`] because it is a
    /// different instruction to the caller: report the divergence AND put these
    /// frames on the wire. A drop that silently carried recovery traffic in a
    /// field most call sites ignore is how the recovery would get lost.
    Forked {
        reason: String,
        outbound: Vec<String>,
    },
}

/// The per-connection MLS session.
pub struct MlsSession {
    pub room: String,
    handle: String,
    identity: MlsIdentity,
    provider: DurableProvider,
    pins: PinStore,
    ledger: ConsumedLedger,
    group: Option<MlsGroup>,
    genesis: Option<GenesisAssertion>,
    trust: Option<GenesisTrust>,
    fork: ForkSignal,
    enc_pinned: bool,
    /// A `roomcfg :enc false` conflicted with the pin: fail closed.
    downgrade_refused: bool,
    meta_path: PathBuf,
    /// SPEC-024 per-room protocol-version flag (ADR-034): true on a mls-ds/v1 room, activating
    /// H7 owner-removal rejection and the pull loop. Loaded from `SessionMeta.protocol_version`.
    is_v1: bool,
    /// The wire identity (signs idkey/bye assertions — same key as the MLS
    /// leaf, different DS labels).
    wire_seed: [u8; 32],
    /// SPEC-061 REQ-008: the pairing admission grant a member signed for us, as
    /// JSON. Held whether or not we can use it yet — it arrives when its signer
    /// is online and is redeemed when the hub will serve us a GroupInfo, and
    /// those are not always the same moment.
    pair_grant: Option<String>,
    /// The room roster from the last `presence` frame. Tracked so that when a
    /// NEW handle appears we re-broadcast our own `idkey` (REQ-019) — the
    /// hub fans an `idkey` only once at join, to then-connected members, so a
    /// late joiner would otherwise never receive an earlier member's key and
    /// could not pin it for the REQ-008 adder check.
    present: std::collections::HashSet<String>,
    /// SPEC-061 REQ-008 — an external Commit we have built and sent but that
    /// nobody has acknowledged yet.
    ///
    /// It is held HERE rather than in `group` because installing it there is what
    /// spends the grant: `self_seat_frames` will not act while a group is held,
    /// so a commit that lost the ordering race used to leave the agent with a
    /// phantom epoch, no way to re-seat, and no way to tell. That is cbcl-bus
    /// BUG-022 from the joiner's side — "the grant MUST NOT be spent until the
    /// join is acknowledged".
    ///
    /// RFC 9420 §14 is explicit that a joiner's own build succeeds whether or not
    /// the Commit is accepted, so holding the group is NOT evidence that anyone
    /// agreed. The evidence is the hub fanning our own Commit back to us.
    pending_seat: Option<PendingSeat>,
    /// The highest GroupInfo epoch seen for this room.
    ///
    /// Every member republishes a GroupInfo after every merged handshake, so in a
    /// room with several members a joiner receives several — including stale ones
    /// from members that merged a moment ago. Building against the first one that
    /// arrives is building against whichever member's frame won a race, which is
    /// how a self-seating agent ends up committing at an epoch the room has
    /// already left.
    seen_gi_epoch: Option<u64>,
    /// Consecutive refusals on the seating path (SPEC-061 CON-003). Reset by a
    /// GroupInfo we can act on; bounded only so the condition becomes visible,
    /// never so that we stop trying.
    seat_refusals: u32,
    /// SPEC-013 REQ-025(c): resync requests sent since the fork. Its own counter
    /// and NOT the decrypt-failure counter, which is the F4 defect: once the
    /// forked group is discarded nothing decrypts, so no further failures accrue
    /// and a terminal branch keyed on them can never be reached. cbcl-bus shipped
    /// exactly that, and the spec says hark SHALL NOT copy it.
    resync_attempts: u32,
    /// The last resync nonce we emitted, so the next is strictly greater.
    /// Strictly monotonic and NOT the pin epoch (re-review #1): the pin epoch is
    /// constant absent a rotation, so a captured resync could be replayed to
    /// force an eviction.
    last_resync_nonce: u64,
    /// REQ-025(c): the terminal surface has been reported; do not repeat it.
    resync_exhausted: bool,
    /// SPEC-013 REQ-006: set when a fork is detected, cleared by the Commit or
    /// join that ends it. The session's own view of whether it is diverged, so
    /// the transport loop can mirror a fact instead of inferring one.
    fork_active: bool,
    /// REQ-026(a)(ii): the highest resync nonce honoured for each requester.
    ///
    /// A signed resync is capturable off the wire, and honouring one evicts and
    /// re-adds its subject. Without a strictly-increasing floor per handle, a
    /// captured request could be replayed at will to churn a healthy member out
    /// of the group — the request is authentic, which is exactly why the
    /// signature alone is not enough.
    resync_nonces: std::collections::HashMap<String, u64>,
    /// REQ-026(e): honoured resyncs per requester, as `(window index, count)`.
    ///
    /// Keyed on a wall-clock bucket and NOT on the MLS epoch. Each honoured
    /// resync is itself a Remove plus an Add, so it bumps the epoch twice — an
    /// epoch-keyed window would reset on its own trigger and bound nothing
    /// (re-review #2).
    resync_honoured: std::collections::HashMap<String, (u64, u32)>,
    /// REQ-026(c): requesters whose fresh KeyPackage we are waiting for.
    ///
    /// The remove and the add are two Commits driven by frames that arrive at
    /// different times, and the eviction MUST NOT happen until the re-add is
    /// known to be completable (review F5). This is what remembers, between the
    /// `keyget` and the `keypkg`, that this member is being healed rather than
    /// added for the first time.
    resync_heal: std::collections::HashSet<String>,
}

/// Whether honouring a resync may EVICT a live member (SPEC-013 REQ-026(c)).
///
/// **False, and this is a design gap rather than unfinished work.**
///
/// A heal removes the stale leaf and re-adds from a KeyPackage the hub serves in
/// answer to our `keyget`. The only checks available on that package are its
/// credential handle and its leaf signature key — and because a handle's MLS
/// identity is bound to its ONE wire key, every package that handle has ever
/// published, in every room, carries the same signature key. `verify_add_target`
/// therefore cannot tell a package generated by this room's session from one
/// generated by another room's, and their init private keys live in different
/// providers.
///
/// So the hub, which answers the `keyget`, can serve a pin-valid package whose
/// private half this room's peer does not hold. The Remove commits, the re-add
/// produces a leaf nobody can use, and the member is evicted into a Welcome it
/// cannot open — with the roster still listing it, so nothing re-adds it.
///
/// The ordinary Add path has the same exposure and always has; there it costs a
/// failed Add that is retried. Honouring a resync converts it into a committed
/// eviction, which is the difference between a nuisance and NFR-001 — no hub
/// behaviour may decide who is in a group.
///
/// Closing it needs the requester to name the package it can open, inside the
/// signed resync context, so the hub cannot substitute. That is a wire change and
/// belongs in the spec before the code. Until then this client verifies, rate
/// limits, and declines: everything REQ-026 asks for except the eviction itself.
const REPROVISIONING_MAY_EVICT: bool = false;

/// REQ-026(e): honoured resyncs allowed per requester per window.
///
/// Two is not a tuned number: a legitimate heal needs one, and the second covers
/// a heal whose own Commit was lost. Beyond that the member is not recovering,
/// it is draining the room's KeyPackages and churning its epoch.
const RESYNC_RATE: u32 = 2;
/// The wall-clock bucket [`RESYNC_RATE`] is counted against.
const RESYNC_WINDOW_MS: u64 = 60 * 60 * 1000;

/// Consecutive re-request attempts before the desync is surfaced as terminal
/// (SPEC-013 REQ-025(c)).
const RESYNC_CAP: u32 = 3;

/// Another party holds the room's GroupInfo claim. Clears in seconds.
const GROUPINFO_CLAIMED_SLUG: &str = "groupinfo-claimed";
/// The room has published no GroupInfo. Clears when a member republishes, not
/// with time — deliberately NOT the same thing as contention.
const NO_GROUPINFO_SLUG: &str = "no-groupinfo";
/// Refusals tolerated before the stall is logged at `warn` rather than `info`.
/// Not a give-up: an agent that stops asking never gets in at all.
const SEAT_REFUSAL_BUDGET: u32 = 10;

/// An external Commit awaiting acknowledgement (SPEC-061 REQ-008).
struct PendingSeat {
    /// The group as it will be once the Commit is accepted. Not installed until
    /// then, and dropped if a newer GroupInfo makes this attempt stale.
    group: MlsGroup,
    genesis: GenesisAssertion,
    trust: GenesisTrust,
    /// The base64 Commit exactly as it went on the wire — the bytes the hub's
    /// echo is matched against. Matched below the MLS layer deliberately: our own
    /// session would reject its own echoed Commit as already-merged.
    ct_b64: String,
    /// The GroupInfo epoch this Commit was built against.
    epoch: u64,
}

/// The on-disk stem for one agent's MLS state **in one room**.
///
/// Keyed on `(wire handle, room)`, not the handle alone. The signing key is
/// legitimately per-handle — an agent's identity is the same in every channel —
/// but its MLS *group* state is not: a group, its genesis, its pins and its
/// consumed-KeyPackage ledger all belong to one room.
///
/// Sharing one stem across rooms let a second channel open the first's files,
/// find a meta naming another room, filter it out as unusable, and then persist
/// its own over the top — destroying the first channel's `group_id`, `genesis`
/// and `enc_pinned`. The victim resumed with no group, unable to decrypt
/// anything, while `hark daemon status` reported it `connected`.
fn state_stem(file_stem: &str, room: &str) -> String {
    let room: String = room
        .trim_start_matches('@')
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let room = if room.is_empty() {
        "room".to_owned()
    } else {
        room
    };
    format!("{file_stem}.{room}")
}

/// The four files (plus the v1 pin directory) that make up one room's state.
/// `kpledger` is deliberately absent: the consumed-ref ledger is per HANDLE (the
/// KeyPackage directory it tracks is), so its legacy path is already its home
/// and moving it to a per-room stem would re-split the very thing that has to
/// stay whole.
const STATE_SUFFIXES: [&str; 3] = ["mls", "pins", "mlsmeta"];

/// Move pre-per-room state to its per-room stem, once.
///
/// Everything written before the keying was fixed lives at `<handle>.*` and
/// belongs to whichever room its meta names. If that room is this one, it is
/// this session's state and is moved; if it names another room, it is left
/// alone for its rightful owner to claim. An unreadable or absent legacy meta
/// moves nothing — there is no room to attribute it to, and guessing is how the
/// original bug destroyed state in the first place.
fn migrate_legacy_state(
    identity_dir: &Path,
    file_stem: &str,
    stem: &str,
    room: &str,
) -> Result<(), MlsError> {
    if identity_dir.join(format!("{stem}.mlsmeta")).exists() {
        return Ok(()); // already migrated
    }
    let legacy_meta = identity_dir.join(format!("{file_stem}.mlsmeta"));
    let Ok(bytes) = fs::read(&legacy_meta) else {
        return Ok(());
    };
    let owns_this_room = serde_json::from_slice::<SessionMeta>(&bytes)
        .map(|meta| meta.room == room)
        .unwrap_or(false);
    if !owns_this_room {
        return Ok(());
    }
    for suffix in STATE_SUFFIXES {
        let from = identity_dir.join(format!("{file_stem}.{suffix}"));
        let to = identity_dir.join(format!("{stem}.{suffix}"));
        if from.exists() {
            fs::rename(&from, &to)?;
        }
    }
    let from = identity_dir.join(format!("{file_stem}.v1store"));
    if from.exists() {
        fs::rename(&from, identity_dir.join(format!("{stem}.v1store")))?;
    }
    tracing::info!(room, stem, "migrated MLS state to its per-room stem");
    Ok(())
}

impl MlsSession {
    /// Open (or resume) the session state for `(file_stem, room)` under
    /// `identity_dir`. `pinned_encrypted` is the REQ-023 admission-path /
    /// operator-intent signal for THIS join; a previously persisted pin is
    /// never un-pinned by its absence.
    pub fn open(
        identity_dir: &Path,
        file_stem: &str,
        room: &str,
        handle: &str,
        wire: &ChatIdentity,
        pinned_encrypted: bool,
    ) -> Result<Self, MlsError> {
        // The caller passes the per-HANDLE stem (which is also the signing key's).
        // MLS state is per-(handle, room), so derive it here rather than at each
        // call site: one place decides, and neither caller can get it wrong.
        let stem = state_stem(file_stem, room);
        migrate_legacy_state(identity_dir, file_stem, &stem, room)?;
        let provider = DurableProvider::open(&identity_dir.join(format!("{stem}.mls")))?;
        let pins = PinStore::open(&identity_dir.join(format!("{stem}.pins")))?;
        // PER-HANDLE, not per-room, and that mismatch was a live NFR-001 hole.
        //
        // MLS group state is per (handle, room) — a group, its genesis and its
        // pins all belong to one room. A KeyPackage does not: `keypub`/`keyget`
        // are addressed to `@hub` and name no room, so the directory is global
        // to the handle and one package can be served into any room.
        //
        // With the ledger split per room, a package spent in room A was unknown
        // in room B. On the REQ-026 heal path that let the hub — which answers
        // the `keyget` — serve a foreign but pin-valid package, commit the
        // Remove against a re-add whose init key nobody in that room holds, and
        // strand the member it was asked to help. The ledger has to be scoped to
        // what it tracks, not to what it sits beside.
        let ledger_path = identity_dir.join(format!("{file_stem}.kpledger"));
        let mut ledger = ConsumedLedger::open(&ledger_path)?;
        // Consolidate any per-room ledgers left by the old scoping. Forgetting a
        // consumed ref IS the vulnerability, so this absorbs rather than
        // replaces.
        if let Ok(entries) = fs::read_dir(identity_dir) {
            let prefix = format!("{file_stem}.");
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with(&prefix) && name.ends_with(".kpledger") && entry.path() != ledger_path {
                    ledger.absorb(&entry.path())?;
                }
            }
        }
        let meta_path = identity_dir.join(format!("{stem}.mlsmeta"));

        let meta: Option<SessionMeta> = match fs::read(&meta_path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(MlsError::Storage(e)),
            Ok(bytes) => serde_json::from_slice(&bytes)
                .ok()
                .filter(|m: &SessionMeta| m.version == META_VERSION && m.room == room),
        };

        let identity = MlsIdentity::from_wire_identity(wire, handle);
        let mut session = Self {
            room: room.to_string(),
            handle: handle.to_string(),
            identity,
            provider,
            pins,
            ledger,
            group: None,
            genesis: None,
            trust: None,
            fork: ForkSignal::default(),
            enc_pinned: pinned_encrypted,
            downgrade_refused: false,
            meta_path,
            is_v1: false,
            wire_seed: wire.signing_seed(),
            pair_grant: None,
            present: std::collections::HashSet::new(),
            pending_seat: None,
            seen_gi_epoch: None,
            seat_refusals: 0,
            resync_attempts: 0,
            last_resync_nonce: 0,
            resync_exhausted: false,
            fork_active: false,
            resync_nonces: std::collections::HashMap::new(),
            resync_honoured: std::collections::HashMap::new(),
            resync_heal: std::collections::HashSet::new(),
        };

        if let Some(meta) = meta {
            session.enc_pinned = session.enc_pinned || meta.enc_pinned;
            session.is_v1 = meta.protocol_version >= 1;
            session.genesis = meta.genesis;
            session.pair_grant = meta.pair_grant;
            // REQ-026(a)(ii)/(e): restore the replay floor and the rate-limit
            // budget. Without this a restart is a free reset of both, and a
            // captured resync replays.
            session.resync_nonces = meta.resync_nonces;
            session.resync_honoured = meta.resync_honoured;
            // Reload the persisted group (REQ-009): a missing/stale state
            // simply means re-join (logged by the provider open path).
            if let Some(group_id_b64) = meta.group_id_b64 {
                if let Ok(group_id) = B64.decode(&group_id_b64) {
                    use openmls_traits::OpenMlsProvider as _;
                    session.group =
                        MlsGroup::load(session.provider.storage(), &GroupId::from_slice(&group_id))
                            .ok()
                            .flatten();
                    if session.group.is_some() && session.genesis.is_some() {
                        // Restore the trust grade faithfully: a group joined as
                        // unconfirmed TOFU stays TOFU-pending across restart so
                        // the safety-number comparison is still required; only a
                        // group that was authoritative at join (pinned creator
                        // key) reloads authoritative.
                        session.trust = Some(if meta.tofu_pending {
                            GenesisTrust::TofuRequiresSafetyNumber
                        } else {
                            GenesisTrust::Authoritative
                        });
                    }
                }
            }
        }
        session.persist_meta()?;
        Ok(session)
    }

    /// Open a session only when one is warranted: the channel is pinned
    /// encrypted by this join's admission path, or prior MLS session state
    /// exists for this agent. Plain public channels get `None` and keep the
    /// pre-SPEC-013 plaintext path untouched.
    pub fn open_if_relevant(
        identity_dir: &Path,
        file_stem: &str,
        room: &str,
        handle: &str,
        wire: &ChatIdentity,
        pinned_encrypted: bool,
    ) -> Result<Option<Self>, MlsError> {
        // State belonging to THIS room — either already at the per-room stem, or
        // still at the legacy per-handle stem with a meta naming this room.
        // Keying this on the handle alone handed a public channel a session
        // merely because some other channel had left state behind.
        let stem = state_stem(file_stem, room);
        let has_state = identity_dir.join(format!("{stem}.mlsmeta")).exists()
            || fs::read(identity_dir.join(format!("{file_stem}.mlsmeta")))
                .ok()
                .and_then(|bytes| serde_json::from_slice::<SessionMeta>(&bytes).ok())
                .is_some_and(|meta| meta.room == room);
        if !pinned_encrypted && !has_state {
            return Ok(None);
        }
        Self::open(
            identity_dir,
            file_stem,
            room,
            handle,
            wire,
            pinned_encrypted,
        )
        .map(Some)
    }

    fn persist_meta(&self) -> Result<(), MlsError> {
        let meta = SessionMeta {
            version: META_VERSION,
            room: self.room.clone(),
            enc_pinned: self.enc_pinned,
            group_id_b64: self
                .group
                .as_ref()
                .map(|g| B64.encode(g.group_id().as_slice())),
            genesis: self.genesis.clone(),
            tofu_pending: matches!(self.trust, Some(GenesisTrust::TofuRequiresSafetyNumber)),
            protocol_version: if self.is_v1 { 1 } else { 0 },
            pair_grant: self.pair_grant.clone(),
            resync_nonces: self.resync_nonces.clone(),
            resync_honoured: self.resync_honoured.clone(),
        };
        let bytes = serde_json::to_vec(&meta).map_err(std::io::Error::other)?;
        if let Some(parent) = self.meta_path.parent() {
            fs::create_dir_all(parent)?;
        }
        // Atomic write (temp + fsync + rename), matching the provider/pins/
        // ledger writers — a crash mid-write must not truncate the resume
        // state and silently force a re-join (REQ-009).
        let tmp = self.meta_path.with_extension("mlsmeta.tmp");
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &self.meta_path)?;
        Ok(())
    }

    /// Is the channel pinned encrypted (REQ-023)?
    pub fn encrypted(&self) -> bool {
        self.enc_pinned
    }

    /// Is the session in the failed-closed downgrade state?
    pub fn downgrade_refused(&self) -> bool {
        self.downgrade_refused
    }

    /// Member of a live group?
    pub fn joined(&self) -> bool {
        self.group.is_some()
    }

    /// Mark this room as `mls-ds/v1` (ADR-034): activates H7 owner-removal rejection and the
    /// pull loop, and persists the flag. Called by the v1-room creation path (claim → genesis).
    pub fn mark_v1(&mut self) -> Result<(), MlsError> {
        self.is_v1 = true;
        self.persist_meta()
    }

    /// Whether this room speaks `mls-ds/v1` (ADR-034).
    pub fn is_v1(&self) -> bool {
        self.is_v1
    }

    /// The pull task's pin directory (genesis anchor + TOFU DS key), colocated
    /// with the session's resume state.
    pub fn v1_pins_dir(&self) -> std::path::PathBuf {
        self.meta_path.with_extension("v1pins")
    }

    /// CON-013 (ADR-033): persist the v1 client-state tuple AND the OpenMLS provider snapshot in
    /// ONE atomic commit (the `store.rs` manifest-flip), so a crash never exposes a group-vs-cursor
    /// mix (REQ-083). v1 rooms use this INSTEAD of the separate `persist_meta` + provider renames;
    /// legacy rooms keep their format — no on-disk migration, since v1 rooms are new.
    pub fn persist_v1_state(
        &self,
        generation: u64,
        log: &crate::mls_ds::ClientLog,
    ) -> Result<(), MlsError> {
        let snapshot = self.provider.snapshot_bytes()?;
        let store =
            crate::mls_ds::store::DurableStore::open(self.meta_path.with_extension("v1store"));
        store
            .commit_client_state(generation, &snapshot, log)
            .map_err(MlsError::Storage)
    }

    /// Reload the v1 client state committed by [`Self::persist_v1_state`] — whole-old or whole-new,
    /// never mixed (CON-013). `(generation, provider_snapshot, ClientLog)` or None if absent.
    pub fn load_v1_state(&self) -> Option<(u64, Vec<u8>, crate::mls_ds::ClientLog)> {
        let store =
            crate::mls_ds::store::DurableStore::open(self.meta_path.with_extension("v1store"));
        store.load_client_state()
    }

    /// REQ-023: judge a `roomcfg` frame against the pin. `:enc false` on a
    /// pinned channel is a downgrade attack → fail closed. `:enc true` on an
    /// unpinned channel may bootstrap MLS (never the downgrade direction)
    /// but does NOT pin.
    pub fn on_roomcfg(&mut self, text: &str) -> Result<(), MlsError> {
        let enc = kw_bool(text, ":enc");
        match enc {
            Some(false) if self.enc_pinned => {
                self.downgrade_refused = true;
                Err(MlsError::Rejected(format!(
                    "hub sent roomcfg :enc false for {} which is pinned encrypted — downgrade \
                     refused, failing closed (REQ-023)",
                    self.room
                )))
            }
            _ => Ok(()),
        }
    }

    /// The frames to send right after a successful join into a pinned
    /// encrypted channel: KeyPackage publication (REQ-002) and the
    /// self-signed `idkey` assertion (REQ-019).
    pub fn join_frames(&mut self) -> Result<Vec<String>, MlsError> {
        if !self.enc_pinned {
            return Ok(Vec::new());
        }
        let mut frames = Vec::new();

        let last = build_last_resort(&self.provider, &self.identity)?;
        let one_time = build_one_time(&self.provider, &self.identity, ONE_TIME_POOL_TARGET)?;
        let onetime_list = one_time
            .iter()
            .map(|p| format!("\"{}\"", B64.encode(&p.bytes)))
            .collect::<Vec<_>>()
            .join(" ");
        frames.push(format!(
            "(keypub @hub :last \"{}\" :onetime ({}) :from {})",
            B64.encode(&last.bytes),
            onetime_list,
            self.handle
        ));

        frames.push(self.own_idkey_frame()?);
        // SPEC-013 IB-3: announce "published, add me" so a web owner has an
        // explicit, re-drivable add trigger (not just presence timing).
        frames.push(self.keyready_frame());

        // SPEC-061 REQ-008: if we are still not a member, ask whether somebody
        // signed an admission for us while we were away. The fan that carries a
        // fresh grant only reaches an agent that is connected, and the case this
        // credential exists for is precisely the one where we were not.
        //
        // Asked on every join rather than only after a failure: an agent that
        // cannot decrypt has no other moment to notice, and the answer is one
        // small frame the hub refuses cheaply when there is nothing to give.
        if self.group.is_none() {
            frames.push(format!("(pairgrantget {} :for {} :from {})", self.room, self.handle, self.handle));
        }
        // …and if we already hold one, go straight for the GroupInfo.
        frames.extend(self.self_seat_frames());
        Ok(frames)
    }

    /// Build this agent's self-signed `idkey` assertion frame (REQ-019),
    /// bound to the current pin epoch. Broadcast at join and re-broadcast
    /// whenever a new member appears in `presence`, so late joiners can pin
    /// us for the REQ-008 adder check.
    fn own_idkey_frame(&self) -> Result<String, MlsError> {
        let key = <[u8; 32]>::try_from(self.identity.public_key())
            .map_err(|_| MlsError::Rejected("identity key is not 32 bytes".into()))?;
        let nonce: u64 = self
            .pins
            .pinned(&self.handle)
            .map(|p| p.pin_epoch)
            .unwrap_or(0);
        let wire = ChatIdentity::from_seed(self.wire_seed);
        let sig = wire.sign(&idkey_signing_bytes(&self.handle, &key, &self.room, nonce));
        // Addressed to the ROOM (not the asserter's handle) so the hub's
        // membership-gated fan delivers it to every member — the same
        // contract `deliver`/`welcome` use, including the `:from` the hub
        // requires to attribute a room frame (without it the hub rejects the
        // frame `missing-from` and never fans it). The asserter IS the
        // sender, so `:from` carries the handle; the signed context (handle,
        // key, room, nonce) is unchanged.
        Ok(format!(
            "(idkey {} :from {} :key \"{}\" :room {} :nonce {} :sig \"{}\")",
            self.room,
            self.handle,
            B64.encode(key),
            self.room,
            nonce,
            B64.encode(sig)
        ))
    }

    /// A `keyget` for `target` (fetch their KeyPackage to add them).
    fn keyget_frame(&self, target: &str) -> String {
        format!("(keyget @hub :for {target} :from {})", self.handle)
    }

    /// A `keyready` announce — the web owner's canonical "I've published my
    /// KeyPackages, add me" trigger (cbcl-bus mls.js `onPeerReady`, SPEC-013
    /// IB-3). Room-fanned with the `:from` attribution the hub requires for a
    /// room frame, exactly like `idkey`. hark previously relied on presence
    /// timing alone; emitting this gives a weak or late-electing owner an
    /// explicit, re-drivable add trigger.
    fn keyready_frame(&self) -> String {
        format!("(keyready {} :from {})", self.room, self.handle)
    }

    /// If we are the elected owner, a `keyget` for each present member we
    /// have a verified pin for but who is not yet in the group — the Add is
    /// gated on having the pin (REQ-008), so this fires only once the
    /// target's `idkey` has landed.
    fn keygets_for_addable(&self) -> Vec<String> {
        let Some(group) = self.group.as_ref() else {
            return Vec::new();
        };
        if !is_owner(group, &self.identity).unwrap_or(false) {
            return Vec::new();
        }
        let members: std::collections::HashSet<String> = group
            .members()
            .filter_map(|m| super::group::credential_handle(&m.credential).ok())
            .collect();
        self.present
            .iter()
            .filter(|h| {
                **h != self.handle && !members.contains(*h) && self.pins.pinned(h).is_some()
            })
            .map(|h| self.keyget_frame(h))
            .collect()
    }

    /// Operator intent (REQ-023 (b)): create the room's group — the agent is
    /// the room creator. Pins the mode encrypted.
    pub fn create_group_as_creator(&mut self) -> Result<(), MlsError> {
        if self.group.is_some() {
            return Err(MlsError::Rejected(
                "a group already exists for this room (REQ-012c)".into(),
            ));
        }
        self.enc_pinned = true;
        let (group, genesis) = create_group(&self.provider, &self.identity, &self.room)?;
        self.group = Some(group);
        self.genesis = Some(genesis);
        self.trust = Some(GenesisTrust::Authoritative);
        // The creator pins itself (its own key is trivially verified).
        let key = <[u8; 32]>::try_from(self.identity.public_key()).unwrap();
        self.pins.observe_verified(&self.handle, &key)?;
        self.persist_meta()
    }

    /// The handles currently seated in this room's ratchet tree, or `None` when
    /// we hold no group. Read-only, and the counterpart to
    /// [`MlsSession::safety_numbers`] — a safety number says two members agree on
    /// a group, this says who is in it. The SPEC-061 interop check needs it,
    /// because "the frame was Handled" and "the joiner is now a member" are
    /// different claims and only the second is the one worth making.
    pub fn member_handles(&self) -> Option<Vec<String>> {
        let group = self.group.as_ref()?;
        super::group::member_bindings(group)
            .ok()
            .map(|bs| bs.into_iter().map(|(h, _)| h).collect())
    }

    /// SPEC-061 REQ-005: the `(groupinfo …)` frame for this room's CURRENT epoch,
    /// or `None` when we hold no group.
    ///
    /// This is hark's half of external-Commit admission, and it is the half that
    /// matters even though an agent is never the party redeeming an invite: a
    /// joiner needs a `GroupInfo` from *somebody*, so a private channel whose only
    /// online members are agents could otherwise never admit an invited human at
    /// all. Publishing is the whole of what an agent has to do — it validates
    /// external Commits (see `validate_external_commit`) but never mints one.
    ///
    /// Single-use, per RFC 9420 §12.4.3.2: "each GroupInfo object can be used for
    /// one external join, since that external join will cause the epoch to
    /// change." Hence a fresh one after every merged handshake, and the epoch on
    /// the wire so the hub — which cannot parse the object — can keep the newest.
    pub fn group_info_frame(&self) -> Option<String> {
        use openmls::prelude::tls_codec::Serialize as _;
        use openmls_traits::OpenMlsProvider as _;
        let group = self.group.as_ref()?;
        let gi = group
            .export_group_info(self.provider.crypto(), &self.identity.signer, true)
            .ok()?
            .tls_serialize_detached()
            .ok()?;
        Some(format!(
            "(groupinfo {} :epoch {} :gi \"{}\" :from {})",
            self.room,
            group.epoch().as_u64(),
            B64.encode(gi),
            self.handle
        ))
    }

    /// REQ-005 + REQ-023: encrypt one outbound payload as a `deliver :enc
    /// mls` frame, or refuse when failing closed. In a pinned-encrypted
    /// channel there is NO plaintext fallback.
    pub fn encrypt_outbound(&mut self, payload: &str) -> Result<String, MlsError> {
        if self.downgrade_refused {
            return Err(MlsError::Rejected(format!(
                "refusing to send into {}: the hub attempted an encryption downgrade and the \
                 session failed closed (REQ-023)",
                self.room
            )));
        }
        let group = self.group.as_mut().ok_or_else(|| {
            // Transient, not a rejection: the Welcome that makes us a member
            // has not arrived yet. Fail closed (no plaintext fallback,
            // REQ-023) but signal retryable so the caller does not poison the
            // handle over a membership race.
            MlsError::NotReady(format!(
                "not yet a member of {}'s MLS group; cannot send encrypted content (and will \
                 not fall back to plaintext — REQ-023)",
                self.room
            ))
        })?;
        let ct = encrypt_message(&self.provider, &self.identity, group, payload.as_bytes())?;
        Ok(format!(
            "(deliver {} :enc mls :ct \"{}\" :from {})",
            self.room,
            B64.encode(ct),
            self.handle
        ))
    }

    /// Route one inbound payload. MLS frames (`welcome`, `deliver`, `keypkg`,
    /// `idkey`, `presence` when owner) are consumed here; anything else is
    /// `NotMls` for the existing plaintext path.
    pub fn handle_frame(&mut self, text: &str) -> SessionEvent {
        let Some(performative) = head_symbol(text) else {
            return SessionEvent::NotMls;
        };
        match performative.as_str() {
            // SPEC-061 CON-003 — the JOINER path's refusals. Consumed only when
            // they are ours; every other error still falls through to the
            // plaintext path so an operator keeps seeing them.
            "error" => self.on_error(text),
            // SPEC-013 REQ-026: a member asking to be re-provisioned. Ignored
            // entirely before this, which is why an all-agent channel had no
            // re-provisioner and a forked agent could only be re-paired by hand.
            "keyready" => self.on_keyready(text),
            "roomcfg" => match self.on_roomcfg(text) {
                Ok(()) => SessionEvent::NotMls, // also a join ack; let the loop see it
                Err(e) => SessionEvent::Dropped {
                    reason: e.to_string(),
                    probable_fork: false,
                },
            },
            "idkey" => self.on_idkey(text),
            "welcome" => self.on_welcome(text),
            // SPEC-061 REQ-008 — the two halves of seating ourselves.
            "pairgrant" => self.on_pairgrant(text),
            "groupinfo" => self.on_groupinfo(text),
            "deliver" => self.on_deliver(text),
            "keypkg" => self.on_keypkg(text),
            "presence" if self.enc_pinned => self.on_presence(text),
            _ => SessionEvent::NotMls,
        }
    }

    /// REQ-019: verify and pin from a fanned `idkey` assertion. Pinning a
    /// newly-seen member is the event that unblocks adding them — so if we
    /// are the elected owner and they are present, fetch their KeyPackage now
    /// (this is what makes the add work regardless of whether the `idkey` or
    /// the `presence` arrived first).
    fn on_idkey(&mut self, text: &str) -> SessionEvent {
        let result = (|| -> Result<String, MlsError> {
            // The asserter is the sender (`:from`); the frame is addressed to
            // the room so the hub fans it. Ignore our own re-broadcast echo.
            let handle = kw_symbol(text, ":from")
                .ok_or_else(|| MlsError::Rejected("idkey missing :from".into()))?;
            if handle == self.handle {
                return Ok(handle);
            }
            let key = kw_bytes32(text, ":key")
                .ok_or_else(|| MlsError::Rejected("idkey missing :key".into()))?;
            let room = kw_symbol(text, ":room")
                .ok_or_else(|| MlsError::Rejected("idkey missing :room".into()))?;
            let nonce = kw_u64(text, ":nonce").unwrap_or(0);
            let sig = kw_b64(text, ":sig")
                .ok_or_else(|| MlsError::Rejected("idkey missing :sig".into()))?;
            self.pins
                .apply_idkey(&handle, &key, &room, nonce, &sig, &self.room)?;
            Ok(handle)
        })();
        match result {
            Ok(_handle) => SessionEvent::Handled {
                outbound: self.keygets_for_addable(),
            },
            Err(e) => SessionEvent::Dropped {
                reason: e.to_string(),
                probable_fork: false,
            },
        }
    }

    /// SPEC-061 REQ-008: a member has signed an admission for us.
    ///
    /// Stored first and durably, then acted on. The two are separable in time —
    /// the grant arrives when its signer is online, and it can only be redeemed
    /// when the hub will serve us a GroupInfo — and treating them as one moment
    /// is how an agent ends up holding an entitlement it forgot across a restart.
    ///
    /// Nothing is verified here, and there is nothing here that could be: a grant
    /// is checked against the ratchet tree it authorises entry to, and we do not
    /// have that tree yet. A grant that is junk, forged, or for somebody else
    /// builds a commit every member refuses, which is where the check belongs.
    /// What we DO check is that it names us — not for security, but because acting
    /// on a grant for another agent means burning a GroupInfo claim to build a
    /// commit that is certain to be rejected.
    fn on_pairgrant(&mut self, text: &str) -> SessionEvent {
        match kw_symbol(text, ":for") {
            Some(subject) if subject == self.handle => {}
            _ => return SessionEvent::Handled { outbound: vec![] },
        }
        let Some(grant) = kw_b64(text, ":grant")
            .and_then(|bytes| String::from_utf8(bytes).ok())
        else {
            return SessionEvent::Dropped {
                reason: "pairgrant :grant is not base64 of UTF-8".into(),
                probable_fork: false,
            };
        };
        self.pair_grant = Some(grant);
        if let Err(e) = self.persist_meta() {
            return SessionEvent::Dropped {
                reason: e.to_string(),
                probable_fork: false,
            };
        }
        SessionEvent::Handled {
            outbound: self.self_seat_frames(),
        }
    }

    /// Ask for the GroupInfo we would need to seat ourselves, if that is our
    /// situation. Empty in every other case, so a caller can send it unconditionally.
    ///
    /// The hub CLAIMS its epoch when it serves one (SPEC-063 REQ-001), and that
    /// claim — not a roster check here — is what stops our external Commit racing
    /// a member's Add for the same epoch. A client-side gate would be guessing from
    /// a presence list the hub composes; the claim is one decision, taken in one
    /// transaction, by the only party that sees every contender.
    fn self_seat_frames(&self) -> Vec<String> {
        if !self.enc_pinned || self.group.is_some() || self.pair_grant.is_none() {
            return Vec::new();
        }
        // An unacknowledged attempt is still an attempt. Asking again would build
        // a second external Commit against a second GroupInfo while the first is
        // still in flight — two Commits from us for one epoch, which is the
        // conflict this path exists to avoid rather than cause.
        if self.pending_seat.is_some() {
            return Vec::new();
        }
        vec![format!("(groupinfoget {} :from {})", self.room, self.handle)]
    }

    /// SPEC-061 REQ-008 / CON-001: the hub served a GroupInfo. If we hold a grant
    /// and no group, this is the moment — nobody has to be online, which is the
    /// whole point of the credential.
    ///
    /// The commit MUST go out. Until it does we are alone at an epoch nobody else
    /// has, which reads to us exactly like being a member and to everybody else
    /// like nothing happened.
    fn on_groupinfo(&mut self, text: &str) -> SessionEvent {
        if self.group.is_some() {
            return SessionEvent::Handled { outbound: vec![] };
        }
        let Some(grant) = self.pair_grant.clone() else {
            return SessionEvent::Handled { outbound: vec![] };
        };
        let Some(gi) = kw_b64(text, ":gi") else {
            return SessionEvent::Dropped {
                reason: "groupinfo missing :gi".into(),
                probable_fork: false,
            };
        };
        // REQ-005 puts the epoch on the wire because the hub cannot parse a
        // GroupInfo and so cannot tell which one is newest. Reading it is the
        // difference between seating against the room's current state and
        // seating against whichever member's republication reached us first.
        //
        // A GroupInfo is single-use (RFC 9420 §12.4.3.2) and every member
        // republishes after every merged handshake, so several arrive and the
        // older ones are already spent. Building on one of those produces a
        // Commit every member refuses for `WrongEpoch` — and, before this, an
        // agent that then believed it was a member.
        let epoch = match kw_u64(text, ":epoch") {
            Some(epoch) => epoch,
            None => {
                return SessionEvent::Dropped {
                    reason: "groupinfo missing :epoch".into(),
                    probable_fork: false,
                };
            }
        };
        if self.seen_gi_epoch.is_some_and(|seen| epoch < seen) {
            return SessionEvent::Handled { outbound: vec![] }; // stale; a newer one is in hand
        }
        self.seen_gi_epoch = Some(epoch);
        self.seat_refusals = 0; // the room answered; the run of refusals is over
        // A newer GroupInfo means the attempt in flight was built against an
        // epoch the room has left, so it cannot be accepted. Drop it and build
        // again — the grant was never spent, which is the point of holding it.
        if let Some(pending) = &self.pending_seat {
            if epoch <= pending.epoch {
                return SessionEvent::Handled { outbound: vec![] };
            }
            tracing::info!(
                room = %self.room, stale = pending.epoch, fresh = epoch,
                "a newer GroupInfo arrived — rebuilding the external Commit against it"
            );
            self.pending_seat = None;
        }
        match join_by_grant(
            &self.provider,
            &self.identity,
            &gi,
            &self.room,
            &grant,
            &mut self.pins,
        ) {
            Ok(joined) => {
                let commit = B64.encode(&joined.commit);
                // NOT installed as `self.group`, and the meta is NOT persisted.
                // Both of those are how the grant gets spent, and until the hub
                // fans this Commit back there is no evidence anybody accepted it.
                // A build that succeeds proves only that we can construct a
                // Commit, which RFC 9420 §14 says is true whether or not it wins.
                self.pending_seat = Some(PendingSeat {
                    group: joined.group,
                    genesis: joined.genesis,
                    trust: joined.trust,
                    ct_b64: commit.clone(),
                    epoch,
                });
                tracing::info!(
                    room = %self.room, epoch,
                    "sent an external Commit to seat ourselves (SPEC-061 REQ-008) — \
                     awaiting the hub's echo before treating it as accepted"
                );
                SessionEvent::Handled {
                    outbound: vec![format!(
                        "(deliver {} :enc mls :ct \"{}\" :from {})",
                        self.room, commit, self.handle
                    )],
                }
            }
            Err(e) => SessionEvent::Dropped {
                reason: format!("external join refused: {e}"),
                probable_fork: false,
            },
        }
    }

    /// SPEC-013 REQ-025 — fork recovery, member side.
    ///
    /// Our epoch has forked from the live group: we can no longer process its
    /// Commits or read its messages, and nothing about that resolves by waiting.
    /// Before this, hark warned and kept the dead group forever, which is the
    /// state an agent was found in — encrypting happily to an epoch nobody was
    /// on, for hours, reporting `connected`.
    ///
    /// **(a) Discard this group's records ONLY.** `MlsGroup::delete` is scoped to
    /// the group id, and OpenMLS explicitly does not manage signature material,
    /// so the identity keystore survives — as does every unconsumed KeyPackage
    /// init private key, which is stored under its own hash ref rather than the
    /// group's. Both are required to open the re-admission Welcome, and a
    /// whole-provider wipe would permanently brick recovery (review F8).
    ///
    /// **(b) Ask to be re-admitted, authenticated.** An unsigned request is a
    /// hub-forgeable eviction of a healthy member, so it is signed under the
    /// dedicated `cbcl-mls-resync/v1` label — domain-separated from the idkey
    /// assertion so neither can be replayed as the other.
    fn begin_resync(&mut self) -> Vec<String> {
        if let Some(group) = self.group.as_mut() {
            if let Err(e) = group.delete(OpenMlsProvider::storage(&self.provider)) {
                // Recovery is still worth attempting: the worst case is that the
                // re-admission Welcome is refused `GroupAlreadyExists`, which is
                // where we already are.
                tracing::warn!(room = %self.room, error = ?e, "discarding the forked group failed");
            }
        }
        self.group = None;
        self.genesis = None;
        self.trust = None;
        self.pending_seat = None;
        let _ = self.provider.persist();
        if let Err(e) = self.persist_meta() {
            tracing::warn!(room = %self.room, error = %e, "resync discard did not persist");
        }
        self.resync_attempts = 0;
        self.resync_exhausted = false;
        self.fork_active = true;
        tracing::warn!(
            room = %self.room,
            "the encrypted session forked from the room and was discarded — \
             requesting re-admission (SPEC-013 REQ-025)"
        );
        // Two routes out, and they are not alternatives — take both.
        //
        // The resync asks a re-provisioner to remove-and-re-add us, which needs
        // one to be online and willing ([[SPEC-013-mls-private-channels#REQ-026]]).
        // The self-seat needs only a GroupInfo from the hub, because the grant
        // already carries a member's permission — and after [[SPEC-061]] REQ-008
        // the discard leaves that grant UNSPENT, so it is still redeemable.
        //
        // Emitting only the resync here left an agent that could seat itself
        // waiting on a roster change to notice, which on a quiet channel is not a
        // wait but a stall. Both frames are no-ops when their preconditions do
        // not hold, so sending them together costs nothing when only one applies.
        let mut frames = self.resync_frames();
        frames.extend(self.self_seat_frames());
        frames
    }

    /// REQ-025(b)/(c): one re-request, or nothing once the cap is spent.
    ///
    /// The cap is counted HERE rather than on decrypt failures. After the discard
    /// there is no group, so no failures accrue and a budget keyed on them never
    /// advances — the F4 defect, which left the shipped web client's terminal
    /// branch unreachable. hark counts what it actually does.
    ///
    /// SIMPLIFY: re-requests are driven by roster changes rather than by
    /// [[SPEC-013-mls-private-channels#REQ-025]](c)'s `RESYNC_WAIT_MS` interval.
    /// `MlsSession` is synchronous — `handle_frame` returns a `SessionEvent` and
    /// owns no timer — so a wall-clock interval needs the chat loop, and a roster
    /// change is the event that can actually make the request answerable (the
    /// re-provisioner has to be present to honour it).
    /// **Ceiling:** a room whose roster never changes re-requests only
    /// `RESYNC_CAP` times across the whole outage — on a quiet channel the
    /// attempts are spent early and the terminal surface arrives late.
    /// **Upgrade path:** a `RESYNC_WAIT_MS` timer in `crate::chat`'s select loop
    /// calling `resync_frames`, which is already idempotent and cap-bounded.
    fn resync_frames(&mut self) -> Vec<String> {
        if self.group.is_some() || !self.enc_pinned {
            return Vec::new();
        }
        if self.resync_attempts >= RESYNC_CAP {
            if !self.resync_exhausted {
                self.resync_exhausted = true;
                tracing::error!(
                    room = %self.room,
                    attempts = self.resync_attempts,
                    "the encrypted session could not be re-established after {RESYNC_CAP} \
                     requests — re-pair this agent into the channel (SPEC-013 REQ-025c)"
                );
            }
            return Vec::new();
        }
        self.resync_attempts += 1;
        // Wall-clock millis, forced strictly upward: a verifier requires the
        // nonce to exceed the last it honoured for us, so two requests inside one
        // millisecond must not tie.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let nonce = now.max(self.last_resync_nonce.saturating_add(1));
        self.last_resync_nonce = nonce;
        let Ok(key) = <[u8; 32]>::try_from(self.identity.public_key()) else {
            return Vec::new();
        };
        let wire = ChatIdentity::from_seed(self.wire_seed);
        let sig = wire.sign(&super::pins::resync_signing_bytes(
            &self.handle,
            &key,
            &self.room,
            nonce,
        ));
        // REQ-025(d): the `:resync` marker is what distinguishes this from a
        // routine re-announce. Only the explicit marker requests re-provisioning,
        // so an ordinary announce can never churn membership.
        vec![format!(
            "(keyready {} :from {} :resync 1 :nonce {} :sig \"{}\")",
            self.room,
            self.handle,
            nonce,
            B64.encode(sig)
        )]
    }

    /// REQ-025(d): a frame we could process means the group is tracking the room
    /// again, so the fork counters go back to zero. Anything that leaves them set
    /// would make the NEXT ordinary dropped frame look like a fresh fork.
    fn clear_resync_state(&mut self) {
        self.resync_attempts = 0;
        self.resync_exhausted = false;
        self.fork_active = false;
        // AND the detector itself, which is the half that mattered and was
        // missing. `ForkSignal::record_success` is called only on the decrypted
        // APPLICATION path in `process_inbound` — a processed Commit never reset
        // it, and a re-admission Welcome does not go through `process_inbound` at
        // all. So a recovered agent resumed still standing at or above
        // FORK_SIGNAL_THRESHOLD, and the next single malformed frame from its own
        // group crossed it again immediately: one bad frame, and the group it had
        // just been re-admitted to was discarded.
        //
        // REQ-025(d) says the counters reset on the next successfully processed
        // Commit or join, and this is the only place all three of those paths
        // meet.
        self.fork.record_success();
    }

    /// SPEC-013 REQ-006: is the encrypted session currently diverged?
    ///
    /// True from the moment a fork is detected until a Commit or a join lands.
    /// Exposed so the transport loop can hold the operator-visible flag to the
    /// session's own view rather than inferring it from event types — inference
    /// is what left the flag set through a recovery that had already succeeded,
    /// because a re-admission Welcome and a processed Commit both report
    /// `Handled`, which is indistinguishable from any other control frame.
    pub fn fork_active(&self) -> bool {
        self.fork_active
    }

    /// SPEC-013 REQ-025(c): recovery is spent and this agent needs an operator.
    ///
    /// Distinct from [`Self::fork_active`], and the distinction is the whole
    /// requirement: a fork is a condition the agent is working through, and this
    /// is the admission that it cannot. Terminal — the agent holds no group, has
    /// asked `RESYNC_CAP` times, and nothing further will happen without a
    /// re-pair.
    pub fn recovery_exhausted(&self) -> bool {
        self.resync_exhausted
    }

    /// REQ-026(c): replace a resyncing member's stale leaf — validate, remove,
    /// re-add, in that order and no other.
    ///
    /// Returns the Remove (carrying its REQ-014 evidence) and the Add's Commit
    /// and Welcome. The Remove is fanned with evidence because every peer
    /// verifies the eviction at merge; without it they reject the Commit and we
    /// desync ourselves trying to help somebody else.
    fn heal_member(&mut self, target: &str, kp_bytes: &[u8]) -> Result<Vec<String>, MlsError> {
        // Validation happens against a borrowed group before anything mutates.
        let group = self
            .group
            .as_mut()
            .ok_or_else(|| MlsError::Rejected("heal without a group".into()))?;
        let kp = validate_key_package_bytes(&self.provider, kp_bytes)?;
        verify_add_target(&kp, target, &self.pins).map_err(|e| {
            // The refusal an operator most needs to read: we asked for a package,
            // got one, and it is not the one this member's pin says it should be.
            // Nothing is removed.
            MlsError::Rejected(format!(
                "refusing to evict {target}: the fetched KeyPackage is not pin-valid, so the \
                 re-add could not complete ({e}) — no eviction without a completable re-add"
            ))
        })?;
        // REQ-013, and the pre-check is incomplete without it. `add_member`
        // refuses a consumed ref — but it refuses it AFTER the Remove has
        // committed, so a package that is pin-valid and already spent evicts the
        // member and then fails to re-add them.
        //
        // That is not a rare shape: the hub owns the KeyPackage directory and
        // answers this very `keyget`, so it can serve a previously-consumed
        // package of the target's own and force-evict any member that asks to be
        // healed. NFR-001 says no hub behaviour may change who is in a group;
        // checking only the pin left the hub exactly that lever, dressed as a
        // valid package.
        let hash_ref = kp
            .hash_ref(self.provider.crypto())
            .map_err(MlsError::stack("hash ref"))?;
        let ref_b64 = B64.encode(hash_ref.as_slice());
        if self.ledger.is_consumed(&ref_b64) {
            return Err(MlsError::Rejected(format!(
                "refusing to evict {target}: the fetched KeyPackage ref {ref_b64} is already \
                 consumed, so the re-add would be refused (REQ-013) — no eviction without a \
                 completable re-add"
            )));
        }

        // Only now is the eviction safe to commit.
        let leaf = group
            .members()
            .find(|m| {
                crate::mls::group::credential_handle(&m.credential)
                    .map(|h| h == target)
                    .unwrap_or(false)
            })
            .ok_or_else(|| MlsError::Rejected(format!("{target} is not a live leaf")))?;
        let leaf_key = <[u8; 32]>::try_from(leaf.signature_key.as_slice())
            .map_err(|_| MlsError::Rejected("target leaf key is not 32 bytes".into()))?;
        let leaf_index = leaf.index.u32();
        let wire = ChatIdentity::from_seed(self.wire_seed);
        let evidence = RemovalEvidence::mint(
            &wire,
            &self.handle,
            &self.room,
            group.group_id().as_slice(),
            group.epoch().as_u64(),
            target,
            leaf_index,
            &leaf_key,
        );
        let creator = group_genesis_creator(group)
            .map(|(handle, _)| handle)
            .unwrap_or_default();
        let remove_ct = crate::mls::removal::remove_member(
            &self.provider,
            &self.identity,
            group,
            &self.room,
            &evidence,
            &self.pins,
            &creator,
            crate::mls::claim::CommitPromise::Inactive,
        )?;
        let evidence_json = serde_json::to_vec(&evidence)
            .map_err(|e| MlsError::Rejected(format!("evidence serialize: {e}")))?;

        // Re-add at the epoch the Remove just produced.
        let group = self
            .group
            .as_mut()
            .ok_or_else(|| MlsError::Rejected("heal lost its group".into()))?;
        let outcome = add_member(
            &self.provider,
            &self.identity,
            group,
            kp_bytes,
            target,
            &self.pins,
            &mut self.ledger,
            &self.room,
            crate::mls::claim::CommitPromise::Inactive,
        )?;
        self.persist_meta()?;
        tracing::info!(
            room = %self.room, target,
            "re-provisioned a resyncing member: stale leaf removed, fresh leaf added (REQ-026)"
        );
        Ok(vec![
            format!(
                "(deliver {} :enc mls :ct \"{}\" :evidence \"{}\" :from {})",
                self.room,
                B64.encode(&remove_ct),
                B64.encode(&evidence_json),
                self.handle
            ),
            format!(
                "(deliver {} :enc mls :ct \"{}\" :from {})",
                self.room,
                B64.encode(&outcome.commit_bytes),
                self.handle
            ),
            format!(
                "(welcome {} :for {} :ct \"{}\" :from {})",
                self.room,
                target,
                B64.encode(&outcome.welcome_bytes),
                self.handle
            ),
        ])
    }

    /// SPEC-013 REQ-026 — honour another member's request to be re-provisioned.    /// SPEC-013 REQ-026 — honour another member's request to be re-provisioned.
    ///
    /// A member whose group forked discards it and asks to be put back
    /// ([[#REQ-025]]). Somebody has to answer, and before this hark never did:
    /// it ignored `keyready` outright, so a channel whose only other members were
    /// agents had no re-provisioner at all and a forked agent could be recovered
    /// only by a human re-pairing it.
    ///
    /// Everything here is a refusal until proven otherwise, because honouring a
    /// request EVICTS its subject. The order matters and is (a)'s: verify before
    /// minting any evidence.
    fn on_keyready(&mut self, text: &str) -> SessionEvent {
        if !self.enc_pinned {
            return SessionEvent::NotMls;
        }
        // REQ-026(d): only an explicit `:resync` marker asks for re-provisioning.
        // A routine re-announce means "I have published my packages" and MUST
        // NOT churn membership — treating the two alike would rebuild the group
        // every time anybody reconnected.
        if kw_u64(text, ":resync") != Some(1) {
            return SessionEvent::NotMls;
        }
        let Some(requester) = kw_symbol(text, ":from") else {
            return SessionEvent::Dropped {
                reason: "resync missing :from".into(),
                probable_fork: false,
            };
        };
        if requester == self.handle {
            return SessionEvent::Handled { outbound: vec![] }; // our own, fanned back
        }
        match self.admit_resync(text, &requester) {
            Ok(outbound) => SessionEvent::Handled { outbound },
            Err(reason) => {
                // Refusing is the ordinary outcome, not an error condition: most
                // of these are a member that is not ours to heal.
                tracing::info!(room = %self.room, %requester, %reason, "resync request not honoured");
                SessionEvent::Handled { outbound: vec![] }
            }
        }
    }

    /// The REQ-026 gate. `Ok` returns the frames to send; `Err` is why not.
    fn admit_resync(&mut self, text: &str, requester: &str) -> Result<Vec<String>, String> {
        let group = self.group.as_ref().ok_or("we hold no group to re-provision into")?;

        // (b) Creator AND elected owner. Only the creator may mint the
        // liveness-fallback removal evidence, and only the owner may commit — so
        // when those principals differ, healing is unavailable here rather than
        // half-possible. Any group admitting a member that sorts before the
        // creator shifts the election away from it (review F3), and a Commit we
        // are not entitled to make is one every peer rejects: we would evict
        // nobody and desync ourselves.
        let creator = group_genesis_creator(group)
            .map(|(handle, _)| handle)
            .ok_or("this group carries no genesis creator")?;
        if creator != self.handle {
            return Err(format!("we are not the room creator ({creator} is)"));
        }
        // Retained, and currently UNREACHABLE. `elect_committer` prefers the
        // genesis creator whenever the creator is a live leaf, so passing the
        // check above already implies passing this one — the two cannot be
        // mutation-killed independently, only jointly.
        //
        // SPEC-013's rationale for this clause cites review F3 ("any group that
        // admits a member lexicographically before the creator shifts the elected
        // owner away from it"), which describes `elect_owner`, not the election
        // this path actually uses. Kept because the day those two elections
        // diverge again this is the check that matters, and removing it would
        // make that divergence silent — but the spec should stop claiming it is
        // separately verified.
        if !is_owner(group, &self.identity).map_err(|e| e.to_string())? {
            return Err("we are not the elected owner of the current tree".into());
        }

        // (a)(i) Verify under the requester's PINNED key, never a key the frame
        // supplies. A request that carries its own key proves only that whoever
        // wrote it holds that key — which a hub does.
        let nonce = kw_u64(text, ":nonce").ok_or("resync missing :nonce")?;
        let sig = kw_b64(text, ":sig").ok_or("resync missing :sig")?;
        let pin = self
            .pins
            .pinned(requester)
            .ok_or("no pinned key for the requester")?;
        let key = pin.key;
        {
            use ed25519_dalek::{Signature, Verifier, VerifyingKey};
            let signed = super::pins::resync_signing_bytes(requester, &key, &self.room, nonce);
            let vk = VerifyingKey::from_bytes(&key)
                .map_err(|_| "pinned key is not a valid Ed25519 key".to_owned())?;
            let sig = Signature::from_slice(&sig)
                .map_err(|_| "resync signature is malformed".to_owned())?;
            vk.verify(&signed, &sig)
                .map_err(|_| "resync signature does not verify under the pinned key".to_owned())?;
        }

        // (a)(ii) Strictly monotonic per requester. A signed resync is capturable,
        // and replaying one evicts a healthy member — so freshness is not
        // ceremony on top of the signature, it is the half the signature cannot
        // provide.
        if let Some(&last) = self.resync_nonces.get(requester) {
            if nonce <= last {
                return Err(format!("stale resync nonce {nonce} (last honoured {last})"));
            }
        }

        // (d) A requester that is not a live leaf is not being re-provisioned —
        // there is no stale leaf to evict. It may be addable as an ordinary
        // member, which `keygets_for_addable` already covers, so this path
        // declines rather than inventing a second way to add somebody.
        let members = member_bindings(group).map_err(|e| e.to_string())?;
        if !members.iter().any(|(handle, _)| handle == requester) {
            return Err("requester is not a live leaf; nothing to re-provision".into());
        }

        // (e) Rate-limit, on a wall-clock bucket.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let window = now / RESYNC_WINDOW_MS;
        let entry = self.resync_honoured.entry(requester.to_owned()).or_insert((window, 0));
        if entry.0 != window {
            *entry = (window, 0);
        }
        if entry.1 >= RESYNC_RATE {
            return Err(format!(
                "rate limit: {} resyncs already honoured for this member in this window",
                entry.1
            ));
        }
        // Both prior values kept, so a failed write restores exactly what was
        // there. Clearing the entries instead would hand back a FULL budget and
        // an empty nonce floor — turning a failed write into the reset an
        // attacker wants.
        let prior_nonce = self.resync_nonces.get(requester).copied();
        let prior_budget = *entry;
        entry.1 += 1;
        self.resync_nonces.insert(requester.to_owned(), nonce);

        // MADE DURABLE BEFORE THE REQUEST IS ACTED ON, not after. Crash between
        // honouring and persisting and the floor is back where it was, so the
        // same captured request replays — which is the failure this state exists
        // to prevent, reached through a window instead of through memory.
        //
        // A request we cannot record as honoured is one we must not honour: the
        // cost of refusing is that a genuine member asks again, and the cost of
        // proceeding is a replay we can no longer detect.
        if let Err(e) = self.persist_meta() {
            match prior_nonce {
                Some(n) => self.resync_nonces.insert(requester.to_owned(), n),
                None => self.resync_nonces.remove(requester),
            };
            self.resync_honoured.insert(requester.to_owned(), prior_budget);
            return Err(format!("could not record the resync as honoured ({e})"));
        }

        // (c) Validate BEFORE removing — so the eviction and the fetch are
        // ordered, not merely both intended. The `keypkg` that answers this is
        // what actually performs the remove-then-add, and only once the fetched
        // package is pin-valid.
        // The eviction gate, LAST — after the request has been verified, counted
        // and recorded. A verified request is one we have seen, so it burns its
        // nonce and its budget whether or not we can act on it; leaving them
        // untouched would let a member spam valid resyncs at no cost.
        if !REPROVISIONING_MAY_EVICT {
            return Err(
                "re-provisioning a live member is disabled: the hub chooses which KeyPackage \
                 answers the fetch and none of them can be told apart, so the eviction could \
                 strand the member it is meant to heal (NFR-001)"
                    .into(),
            );
        }
        self.resync_heal.insert(requester.to_owned());
        tracing::info!(
            room = %self.room, requester, nonce,
            "honouring a resync — fetching a fresh KeyPackage before evicting the stale leaf (REQ-026)"
        );
        Ok(vec![format!(
            "(keyget @hub :for {requester} :from {})",
            self.handle
        )])
    }

    /// SPEC-061 CON-003: a refusal on the path that seats us.    /// SPEC-061 CON-003: a refusal on the path that seats us.
    ///
    /// The two slugs look alike and are nothing alike, and the difference is the
    /// only thing a retry can act on:
    ///
    /// - `groupinfo-claimed` — another party holds the room's GroupInfo claim and
    ///   is about to move the epoch. It clears when they are done, in seconds.
    /// - `no-groupinfo` — the room has published none. It clears when some member
    ///   merges a handshake and republishes, which no amount of asking by us will
    ///   cause. A private channel whose members are all offline sits here.
    ///
    /// Neither is a failure and neither is terminal, so both re-arm rather than
    /// give up: `self_seat_frames` asks again on the next roster change. What
    /// they must NOT do is spin — an immediate retry loses the same race faster,
    /// and against `no-groupinfo` it asks a question nothing has answered.
    ///
    /// Returns `NotMls` for anything else so the ordinary error path is unchanged.
    fn on_error(&mut self, text: &str) -> SessionEvent {
        let Some(items) = parse_list(text) else {
            return SessionEvent::NotMls;
        };
        let addressed_to_us = matches!(
            items.get(1),
            Some(SExpr::Atom(Atom::Symbol(room))) if *room == self.room
        );
        if !addressed_to_us {
            return SessionEvent::NotMls;
        }
        let slug = items.iter().find_map(|item| match item {
            SExpr::Atom(Atom::Str(s)) => Some(s.clone()),
            _ => None,
        });
        match slug.as_deref() {
            Some(GROUPINFO_CLAIMED_SLUG) | Some(NO_GROUPINFO_SLUG) => {}
            _ => return SessionEvent::NotMls,
        }
        // Only meaningful while we are trying to seat ourselves. A member that
        // holds a group has no business reading these.
        if self.group.is_some() || self.pair_grant.is_none() {
            return SessionEvent::NotMls;
        }
        self.pending_seat = None; // whatever we were building is not going to land
        self.seat_refusals = self.seat_refusals.saturating_add(1);
        let contended = slug.as_deref() == Some(GROUPINFO_CLAIMED_SLUG);
        if self.seat_refusals >= SEAT_REFUSAL_BUDGET {
            // RFC 9420 §14 names starvation and leaves it to the application. The
            // requirement is that it becomes visible, not that it resolve: an
            // agent that never gets a turn looks to the person who invited it
            // exactly like a permission problem.
            tracing::warn!(
                room = %self.room,
                refusals = self.seat_refusals,
                contended,
                "still cannot seat this agent — it holds an admission grant but the room \
                 has not served it a GroupInfo it could commit against"
            );
        } else {
            tracing::info!(
                room = %self.room,
                refusals = self.seat_refusals,
                contended,
                "seat attempt refused; will ask again on the next roster change"
            );
        }
        SessionEvent::Handled { outbound: vec![] }
    }

    /// SPEC-061 REQ-008: the hub fanned our own external Commit back to us.
    ///
    /// `cbcl-chat-room:fanout/2` excludes nobody — it "fans out exactly once to
    /// every present member (including the sender)" — so the echo is the only
    /// acknowledgement this path has, and it is what finally spends the grant.
    /// Correlated on the frame bytes rather than by MLS processing: our own
    /// session would reject its own Commit as already-merged, so the signal has
    /// to be read below the MLS layer.
    ///
    /// The limit, stated rather than glossed: the echo proves the HUB took and
    /// fanned the Commit, not that every member applied it. That is strictly more
    /// than the previous evidence, which was none.
    fn note_own_seat_echo(&mut self, ct_b64: &str) -> bool {
        let matches = self
            .pending_seat
            .as_ref()
            .is_some_and(|p| p.ct_b64 == ct_b64);
        if !matches {
            return false;
        }
        let pending = self.pending_seat.take().expect("just matched");
        self.group = Some(pending.group);
        self.genesis = Some(pending.genesis);
        self.trust = Some(pending.trust);
        // PROVIDER FIRST, THEN META, and the order is the invariant.
        //
        // `join_by_grant` builds the group into the provider but does not persist
        // it — the pre-SPEC-061 path got away with that because a later inbound
        // frame persisted as a side effect. Installing at the echo has no such
        // follow-up, so without this the group lives only in memory while the
        // meta on disk names it: a restart then reads a meta pointing at records
        // that are not there and reports `persisted group state missing`, which
        // is a fresh way to be seated and unable to prove it.
        //
        // Meta-last is what makes a crash between the two writes survivable. The
        // meta is the pointer; a pointer written before its target is a dangling
        // one, and that is exactly the failure above.
        if let Err(e) = self.provider.persist() {
            tracing::warn!(room = %self.room, error = %e, "seat accepted but group state did not persist");
        }
        if let Err(e) = self.persist_meta() {
            tracing::warn!(room = %self.room, error = %e, "seat accepted but meta did not persist");
        }
        tracing::info!(
            room = %self.room, epoch = pending.epoch,
            "our external Commit was accepted — seated (SPEC-061 REQ-008)"
        );
        true
    }

    /// REQ-001/REQ-012: a Welcome addressed to us.
    fn on_welcome(&mut self, text: &str) -> SessionEvent {
        // Room-fanned: only consume a welcome :for us.
        match kw_symbol(text, ":for") {
            Some(target) if target == self.handle => {}
            _ => return SessionEvent::Handled { outbound: vec![] },
        }
        let result = (|| -> Result<(), MlsError> {
            let ct = kw_b64(text, ":ct")
                .ok_or_else(|| MlsError::Rejected("welcome missing :ct".into()))?;
            let existing = self
                .group
                .as_ref()
                .map(|g| g.group_id().as_slice().to_vec());
            let outcome = join_from_welcome(
                &self.provider,
                &self.identity,
                &ct,
                &self.room,
                &mut self.pins,
                &mut self.ledger,
                existing.as_deref(),
            )?;
            self.group = Some(outcome.group);
            self.genesis = Some(outcome.genesis);
            self.trust = Some(outcome.trust);
            // REQ-025(d): a join is the other thing that ends a fork, and on the
            // recovery path it is THE thing — a re-admission arrives as a Welcome,
            // never as a Commit we could process. Resetting only on a processed
            // Commit left a healed member carrying its fork counters, so the next
            // ordinary dropped frame started from a raised baseline.
            self.clear_resync_state();
            self.persist_meta()
        })();
        match result {
            Ok(()) => SessionEvent::Handled { outbound: vec![] },
            Err(e) => SessionEvent::Dropped {
                reason: e.to_string(),
                probable_fork: false,
            },
        }
    }

    /// REQ-006/REQ-017/REQ-018: an encrypted room frame.
    fn on_deliver(&mut self, text: &str) -> SessionEvent {
        // Our own frame, fanned back. Checked FIRST and before the group guard,
        // because the whole point of the pending seat is that we hold no group
        // yet — the old order reported this as "deliver before MLS join" and
        // discarded the only acknowledgement the self-seating path ever gets.
        if kw_symbol(text, ":from").as_deref() == Some(self.handle.as_str()) {
            if let Some(ct) = kw_str(text, ":ct") {
                if self.note_own_seat_echo(&ct) {
                    // Now that we hold the group, publish a GroupInfo for the
                    // epoch we just moved the room to: ours spent the one the
                    // hub was holding.
                    return SessionEvent::Handled {
                        outbound: self.group_info_frame().into_iter().collect(),
                    };
                }
            }
            // Any other echo of our own is not ours to process — MLS refuses to
            // decrypt what it sent.
            return SessionEvent::Handled { outbound: vec![] };
        }
        let Some(group) = self.group.as_mut() else {
            return SessionEvent::Dropped {
                reason: "deliver before MLS join".into(),
                probable_fork: false,
            };
        };
        let Some(ct) = kw_b64(text, ":ct") else {
            return SessionEvent::Dropped {
                reason: "deliver missing :ct".into(),
                probable_fork: false,
            };
        };
        // Removal evidence rides alongside a Remove commit (REQ-014).
        let evidence: Option<RemovalEvidence> =
            kw_b64(text, ":evidence").and_then(|bytes| serde_json::from_slice(&bytes).ok());
        let genesis = match self.genesis.as_ref() {
            Some(g) => g.clone(),
            None => {
                return SessionEvent::Dropped {
                    reason: "no genesis for this group".into(),
                    probable_fork: false,
                };
            }
        };
        match process_inbound(
            &self.provider,
            group,
            &ct,
            &self.room,
            &mut self.pins,
            &genesis,
            evidence.as_ref(),
            &mut self.fork,
            // ADR-034 per-room protocol version: true on a mls-ds/v1 room (set via mark_v1 on
            // v1-room creation), activating H7 owner-removal rejection in process_inbound.
            self.is_v1,
        ) {
            Ok(Inbound::App {
                plaintext,
                sender_handle,
            }) => {
                self.clear_resync_state();
                let text = String::from_utf8_lossy(&plaintext).into_owned();
                // REQ-018: the inner :from must match the MLS sender.
                if let Some(from) = kw_symbol(&text, ":from") {
                    if let Err(e) = enforce_sender(&from, &sender_handle) {
                        return SessionEvent::Dropped {
                            reason: e.to_string(),
                            probable_fork: false,
                        };
                    }
                }
                SessionEvent::Plaintext {
                    text,
                    sender: sender_handle,
                }
            }
            Ok(Inbound::Handshake) => {
                self.clear_resync_state();
                let _ = self.persist_meta();
                // SPEC-061 REQ-005: the epoch just moved, which spends whatever
                // GroupInfo the room was holding. Publish one for the new epoch,
                // or a member invited to this channel has nothing to join
                // against — and if every other member is an agent, nothing to
                // join against ever. Best-effort: losing one costs a joiner a
                // retry, so it must never break the handshake path.
                SessionEvent::Handled {
                    outbound: self.group_info_frame().into_iter().collect(),
                }
            }
            Ok(Inbound::Dropped {
                reason,
                probable_fork,
            }) => self.drop_or_recover(reason, probable_fork),
            Err(e) => {
                let probable_fork = self.fork.probable_fork();
                self.drop_or_recover(e.to_string(), probable_fork)
            }
        }
    }

    /// One undecryptable frame is noise; `FORK_THRESHOLD` in a row is a fork.
    ///
    /// Below the threshold this is the old behaviour — count it and move on,
    /// because a single dropped frame is an ordinary event on a lossy path.
    /// At it, REQ-025 recovery starts: the run of failures is the evidence that
    /// our epoch and the room's have parted, and waiting does not mend that.
    fn drop_or_recover(&mut self, reason: String, probable_fork: bool) -> SessionEvent {
        if !probable_fork || !self.enc_pinned || self.group.is_none() {
            return SessionEvent::Dropped {
                reason,
                probable_fork,
            };
        }
        let outbound = self.begin_resync();
        SessionEvent::Forked { reason, outbound }
    }

    /// REQ-003/REQ-008: the hub answered our `keyget` — add the member if we
    /// are the elected owner.
    fn on_keypkg(&mut self, text: &str) -> SessionEvent {
        let result = (|| -> Result<Vec<String>, MlsError> {
            let target = kw_symbol(text, ":for")
                .ok_or_else(|| MlsError::Rejected("keypkg missing :for".into()))?;
            let kp = kw_b64(text, ":kp")
                .ok_or_else(|| MlsError::Rejected("keypkg missing :kp".into()))?;
            if kp.is_empty() {
                // Directory miss — nothing to add.
                return Ok(vec![]);
            }
            let group = self
                .group
                .as_mut()
                .ok_or_else(|| MlsError::Rejected("keypkg before MLS join".into()))?;

            // SPEC-013 REQ-026(c) — the heal path: this member is already a live
            // leaf and we are replacing it, not seating it.
            //
            // VALIDATE FIRST. RFC 9420 §7.8 forbids two leaves sharing a
            // signature key, so the stale leaf has to go before the fresh one can
            // land — which means the eviction is committed before the re-add is
            // attempted, and a re-add that then fails cannot be rolled back. So
            // the fetched package is checked against the pin BEFORE anything is
            // removed: no eviction without a completable re-add (review F5).
            //
            // The case this really guards is not a hostile hub but an ordinary
            // one: a member that legitimately rotated its key while its `rekey`
            // was dropped fetches clean and mismatches the pin. Evicting it on
            // the strength of a package we had not checked would strand exactly
            // the member we were trying to help.
            if self.resync_heal.contains(&target) {
                let outcome = self.heal_member(&target, &kp);
                self.resync_heal.remove(&target);
                return outcome;
            }

            let outcome = add_member(
                &self.provider,
                &self.identity,
                group,
                &kp,
                &target,
                &self.pins,
                &mut self.ledger,
                &self.room,
                // SPEC-027 REQ-001: no room declares the epoch capability yet,
                // so no room has activated the protocol and every commit takes
                // the pre-SPEC-063 path. This becomes `Armed(&claim)` when the
                // claim exchange lands; the gate is here now so that wiring is
                // a change to one argument rather than a change to the
                // invariant.
                crate::mls::claim::CommitPromise::Inactive,
            )?;
            self.persist_meta()?;
            Ok(vec![
                format!(
                    "(deliver {} :enc mls :ct \"{}\" :from {})",
                    self.room,
                    B64.encode(&outcome.commit_bytes),
                    self.handle
                ),
                format!(
                    "(welcome {} :for {} :ct \"{}\" :from {})",
                    self.room,
                    target,
                    B64.encode(&outcome.welcome_bytes),
                    self.handle
                ),
            ])
        })();
        match result {
            Ok(outbound) => SessionEvent::Handled { outbound },
            Err(e) => SessionEvent::Dropped {
                reason: e.to_string(),
                probable_fork: false,
            },
        }
    }

    /// Presence drives two things (never a removal — REQ-014):
    /// 1. **idkey re-broadcast** — when a handle we haven't seen before
    ///    appears, re-broadcast our own `idkey` (REQ-019). The hub fans an
    ///    `idkey` only once at join to then-connected members, so without
    ///    this a member that joined before us never receives our key and a
    ///    member that joins after us is invisible to our join-time fan; the
    ///    re-broadcast closes that delivery gap so both sides can pin.
    /// 2. **add prompt** — if we are the elected owner, a `keyget` for each
    ///    present member we have already pinned but not yet added. Members we
    ///    cannot pin yet are skipped here and picked up in [`Self::on_idkey`]
    ///    once their key lands, so the Add never races ahead of the pin.
    fn on_presence(&mut self, text: &str) -> SessionEvent {
        if !self.enc_pinned {
            return SessionEvent::Handled { outbound: vec![] };
        }
        let roster = presence_handles(text);
        let saw_new = roster
            .iter()
            .any(|h| h != &self.handle && !self.present.contains(h));
        for h in &roster {
            self.present.insert(h.clone());
        }

        let mut outbound = Vec::new();
        if saw_new {
            if let Ok(frame) = self.own_idkey_frame() {
                outbound.push(frame);
            }
            // Re-broadcast the keyready trigger too (SPEC-013 IB-3), so an owner
            // that elects/joins after us gets an explicit, re-drivable add signal
            // — the same delivery-gap fix as the idkey re-broadcast above.
            outbound.push(self.keyready_frame());
        }
        outbound.extend(self.keygets_for_addable());
        // REQ-025(c): the same roster change re-requests re-admission while we
        // are groupless. A resync needs the re-provisioner to be PRESENT, so a
        // roster change is not merely a convenient tick — it is the event that
        // can actually make the request answerable.
        outbound.extend(self.resync_frames());
        // SPEC-061 REQ-008 / CON-003: a roster change is the natural moment to
        // ask again for something to seat ourselves against. It is what makes a
        // refused attempt recover without a timer — `groupinfo-claimed` clears
        // when the holder finishes, and `no-groupinfo` clears when a member turns
        // up and republishes, which IS a roster change. Empty unless we hold a
        // grant, hold no group, and have nothing already in flight.
        outbound.extend(self.self_seat_frames());
        SessionEvent::Handled { outbound }
    }

    /// REQ-014 (a): mint the self-signed `bye` evidence for a voluntary
    /// leave, to be fanned room-wide.
    pub fn leave_frame(&mut self) -> Result<String, MlsError> {
        let group = self
            .group
            .as_ref()
            .ok_or_else(|| MlsError::Rejected("not in a group".into()))?;
        let me = group
            .members()
            .find(|m| m.signature_key == self.identity.public_key())
            .ok_or_else(|| MlsError::Rejected("own leaf not found".into()))?;
        let key = <[u8; 32]>::try_from(me.signature_key.as_slice()).unwrap();
        let wire = ChatIdentity::from_seed(self.wire_seed);
        let evidence = RemovalEvidence::mint(
            &wire,
            &self.handle,
            &self.room,
            group.group_id().as_slice(),
            group.epoch().as_u64(),
            &self.handle,
            me.index.u32(),
            &key,
        );
        let json = serde_json::to_vec(&evidence).map_err(std::io::Error::other)?;
        Ok(format!(
            "(bye {} :evidence \"{}\" :from {})",
            self.room,
            B64.encode(json),
            self.handle
        ))
    }

    /// Remove a member as the elected owner, given verified evidence
    /// (REQ-014). Returns the deliver frame carrying commit + evidence.
    pub fn remove_with_evidence(&mut self, evidence: &RemovalEvidence) -> Result<String, MlsError> {
        let creator = self
            .genesis
            .as_ref()
            .map(|g| g.creator_handle.clone())
            .ok_or_else(|| MlsError::Rejected("no genesis".into()))?;
        let group = self
            .group
            .as_mut()
            .ok_or_else(|| MlsError::Rejected("not in a group".into()))?;
        let commit = remove_member(
            &self.provider,
            &self.identity,
            group,
            &self.room,
            evidence,
            &self.pins,
            &creator,
            // As above: inactive until a room activates the protocol.
            crate::mls::claim::CommitPromise::Inactive,
        )?;
        let json = serde_json::to_vec(evidence).map_err(std::io::Error::other)?;
        self.persist_meta()?;
        Ok(format!(
            "(deliver {} :enc mls :ct \"{}\" :evidence \"{}\" :from {})",
            self.room,
            B64.encode(&commit),
            B64.encode(json),
            self.handle
        ))
    }

    /// REQ-024: both safety numbers for the live group.
    pub fn safety_numbers(&self) -> Result<SafetyNumbers, MlsError> {
        let group = self
            .group
            .as_ref()
            .ok_or_else(|| MlsError::Rejected("not in a group".into()))?;
        group_safety_numbers(group)
    }

    /// The genesis trust grade (TOFU joins require an out-of-band
    /// safety-number comparison before the group is treated as authentic).
    pub fn genesis_trust(&self) -> Option<GenesisTrust> {
        self.trust
    }
}

/// REQ-024 offline surface: read the persisted session state (no daemon
/// round-trip) and compute both safety numbers — what `hark safety-number`
/// prints. Stale only by the last persist, which happens on every mutating
/// group operation.
pub fn offline_safety_numbers(
    identity_dir: &Path,
    file_stem: &str,
    room: &str,
) -> Result<(SafetyNumbers, Option<GenesisTrust>), MlsError> {
    // Per-room stem first; fall back to the legacy per-handle one, because this
    // is a READ path and migration only happens when a session is opened — an
    // agent that has not reconnected since the fix still has its state there.
    let stem = state_stem(file_stem, room);
    let meta_path = identity_dir.join(format!("{stem}.mlsmeta"));
    let (meta_path, stem) = if meta_path.exists() {
        (meta_path, stem)
    } else {
        (
            identity_dir.join(format!("{file_stem}.mlsmeta")),
            file_stem.to_owned(),
        )
    };
    let bytes = fs::read(&meta_path).map_err(|e| {
        MlsError::Rejected(format!(
            "no MLS session state at {} ({e}); has this agent joined an encrypted channel?",
            meta_path.display()
        ))
    })?;
    let meta: SessionMeta = serde_json::from_slice(&bytes)
        .map_err(|e| MlsError::Rejected(format!("session meta unreadable: {e}")))?;
    if meta.room != room {
        return Err(MlsError::Rejected(format!(
            "session state is for {}, not {room}",
            meta.room
        )));
    }
    let group_id = meta
        .group_id_b64
        .as_deref()
        .and_then(|b| B64.decode(b).ok())
        .ok_or_else(|| MlsError::Rejected("agent has not joined the MLS group yet".into()))?;
    let provider = DurableProvider::open(&identity_dir.join(format!("{stem}.mls")))?;
    use openmls_traits::OpenMlsProvider as _;
    let group = MlsGroup::load(provider.storage(), &GroupId::from_slice(&group_id))
        .map_err(MlsError::stack("load group"))?
        .ok_or_else(|| MlsError::Rejected("persisted group state missing (re-join)".into()))?;
    let numbers = group_safety_numbers(&group)?;
    Ok((numbers, None))
}

/// Generate a fresh random nonce for ad-hoc needs (not currently used by the
/// pin-epoch nonce, which binds to the pin state instead).
#[allow(dead_code)]
fn random_nonce() -> u64 {
    rand::rng().random()
}

// ---------------------------------------------------------------- CBCL
// keyword plumbing: tiny, total parsers over the already-validated frame.

fn parse_list(text: &str) -> Option<Vec<SExpr>> {
    match cbcl_parser::parse(text).ok()? {
        SExpr::List(items) => Some(items),
        SExpr::Atom(_) => None,
    }
}

/// The head performative symbol.
fn head_symbol(text: &str) -> Option<String> {
    match parse_list(text)?.first()? {
        SExpr::Atom(Atom::Symbol(s)) => Some(s.clone()),
        _ => None,
    }
}

/// The value following keyword `key`, as a raw SExpr.
fn kw_value(text: &str, key: &str) -> Option<SExpr> {
    let items = parse_list(text)?;
    let want = key.trim_start_matches(':');
    let mut iter = items.iter();
    while let Some(item) = iter.next() {
        if let SExpr::Atom(Atom::Keyword(k)) = item {
            if k == want || k == key {
                return iter.next().cloned();
            }
        }
    }
    None
}

fn kw_symbol(text: &str, key: &str) -> Option<String> {
    match kw_value(text, key)? {
        SExpr::Atom(Atom::Symbol(s)) => Some(s),
        SExpr::Atom(Atom::Str(s)) => Some(s),
        _ => None,
    }
}

fn kw_bool(text: &str, key: &str) -> Option<bool> {
    match kw_value(text, key)? {
        SExpr::Atom(Atom::Bool(b)) => Some(b),
        SExpr::Atom(Atom::Symbol(s)) => match s.as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

fn kw_u64(text: &str, key: &str) -> Option<u64> {
    match kw_value(text, key)? {
        SExpr::Atom(Atom::Num(n)) if n >= 0 => Some(n as u64),
        SExpr::Atom(Atom::Str(s)) => s.parse().ok(),
        _ => None,
    }
}

/// A keyword's value as the RAW string on the wire, undecoded.
///
/// Distinct from [`kw_b64`] on purpose: the self-seat echo (SPEC-061 REQ-008) is
/// correlated on the base64 TEXT we emitted, not on the bytes it decodes to, so
/// that the comparison is against exactly what went on the wire.
fn kw_str(text: &str, key: &str) -> Option<String> {
    match kw_value(text, key)? {
        SExpr::Atom(Atom::Str(s)) => Some(s),
        _ => None,
    }
}

fn kw_b64(text: &str, key: &str) -> Option<Vec<u8>> {
    match kw_value(text, key)? {
        SExpr::Atom(Atom::Str(s)) => B64.decode(s).ok(),
        _ => None,
    }
}

fn kw_bytes32(text: &str, key: &str) -> Option<[u8; 32]> {
    <[u8; 32]>::try_from(kw_b64(text, key)?.as_slice()).ok()
}

/// Handles from `(presence @room :members (@a @b …))`.
fn presence_handles(text: &str) -> Vec<String> {
    match kw_value(text, ":members") {
        Some(SExpr::List(items)) => items
            .into_iter()
            .filter_map(|item| match item {
                SExpr::Atom(Atom::Symbol(s)) if s.starts_with('@') => Some(s),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mls::validation::FORK_SIGNAL_THRESHOLD;
    use std::path::PathBuf;

    fn setup(tag: &str, seed: u8, handle: &str) -> (PathBuf, ChatIdentity) {
        let dir = std::env::temp_dir().join(format!(
            "hark-mls-sess-{tag}-{}-{}",
            handle.trim_start_matches('@'),
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        (dir, ChatIdentity::from_seed([seed; 32]))
    }

    /// **S1 regression (SPEC-026 review).** Two agents under ONE wire handle in
    /// two different channels must not share MLS state.
    ///
    /// The state files were keyed on the wire handle alone, so the second
    /// channel's session opened the first's `.mls`/`.pins`/`.kpledger`, found a
    /// meta naming another room, filtered it out — and then `persist_meta()`
    /// wrote its own over the top, destroying the first channel's `group_id`,
    /// `genesis` and `enc_pinned`. The first agent came back with no group,
    /// unable to decrypt anything, while reporting `connected`.
    ///
    /// Harmless-looking before SPEC-026, because a human did the two joins in
    /// sequence. REQ-008 rehydration spawns one task per record concurrently,
    /// which turned it into an automatic race whose winner varies per restart.
    #[test]
    fn two_channels_under_one_wire_handle_do_not_share_mls_state() {
        let (dir, wire) = setup("two-rooms", 91, "@aria");

        // The encrypted channel: a real group, pinned.
        let mut private = MlsSession::open(&dir, "aria", "@priv", "@aria", &wire, true)
            .expect("private session opens");
        private
            .create_group_as_creator()
            .expect("the creator bootstraps the group");
        let group_id = private
            .group
            .as_ref()
            .map(|g| g.group_id().as_slice().to_vec())
            .expect("the private session holds a group");
        assert!(private.encrypted());
        drop(private);

        // A second, PUBLIC channel under the same wire handle. Before the fix
        // this opened the private channel's files and overwrote its meta.
        let public = MlsSession::open_if_relevant(&dir, "aria", "@pub", "@aria", &wire, false)
            .expect("opening the public channel does not error");
        drop(public);

        // The private channel must be exactly as it was left.
        let resumed = MlsSession::open(&dir, "aria", "@priv", "@aria", &wire, false)
            .expect("the private session resumes");
        assert!(
            resumed.encrypted(),
            "the encryption pin must survive another channel opening under the same handle"
        );
        assert_eq!(
            resumed
                .group
                .as_ref()
                .map(|g| g.group_id().as_slice().to_vec()),
            Some(group_id),
            "the private channel's group must survive: losing it strands the agent \
             with no way to decrypt, while status still reads `connected`"
        );
    }

    /// An unrelated channel must not inherit a session from LEGACY state
    /// either — the case the per-room test above cannot reach.
    ///
    /// `has_state` has to consult the legacy meta's `room`, not merely whether a
    /// legacy file exists. Checking existence alone is exactly the original bug:
    /// a public channel is handed a session because some other channel left
    /// state under the shared handle stem.
    #[test]
    fn an_unrelated_channel_does_not_inherit_legacy_state() {
        let (dir, wire) = setup("no-inherit-legacy", 95, "@aria");
        {
            let mut legacy = MlsSession::open(&dir, "aria", "@priv", "@aria", &wire, true)
                .expect("session opens");
            legacy.create_group_as_creator().expect("bootstrap");
        }
        for suffix in ["mls", "pins", "kpledger", "mlsmeta"] {
            let per_room = dir.join(format!("aria.priv.{suffix}"));
            if per_room.exists() {
                fs::rename(&per_room, dir.join(format!("aria.{suffix}"))).expect("stage legacy");
            }
        }
        assert!(dir.join("aria.mlsmeta").exists(), "legacy state is present");

        assert!(
            MlsSession::open_if_relevant(&dir, "aria", "@pub", "@aria", &wire, false)
                .expect("no error")
                .is_none(),
            "an unpinned public channel gets no session from another room's legacy state"
        );
        assert!(
            dir.join("aria.mlsmeta").exists(),
            "and that state is still untouched"
        );
    }

    /// Existing agents keep their group across the keying change.
    ///
    /// Everything written before this fix is at `<handle>.*`. If migration did
    /// not happen, every already-paired agent would silently come back with no
    /// group — the same symptom as the bug, caused by the fix.
    #[test]
    fn legacy_per_handle_state_is_migrated_to_its_room() {
        let (dir, wire) = setup("migrate", 93, "@aria");

        // Lay down state the way a pre-fix build did: at the per-handle stem.
        {
            let mut legacy = MlsSession::open(&dir, "aria", "@priv", "@aria", &wire, true)
                .expect("session opens");
            legacy.create_group_as_creator().expect("bootstrap");
        }
        for suffix in ["mls", "pins", "kpledger", "mlsmeta"] {
            let per_room = dir.join(format!("aria.priv.{suffix}"));
            if per_room.exists() {
                fs::rename(&per_room, dir.join(format!("aria.{suffix}"))).expect("stage legacy");
            }
        }
        assert!(dir.join("aria.mlsmeta").exists(), "staged at the legacy stem");

        let resumed = MlsSession::open(&dir, "aria", "@priv", "@aria", &wire, false)
            .expect("the legacy session resumes");
        assert!(
            resumed.group.is_some(),
            "a pre-fix agent must keep its group across the keying change"
        );
        assert!(resumed.encrypted(), "and its pin");
        assert!(
            dir.join("aria.priv.mlsmeta").exists(),
            "state is moved to the per-room stem, not copied"
        );
        assert!(
            !dir.join("aria.mlsmeta").exists(),
            "and the legacy path is left empty so it cannot be claimed twice"
        );
    }

    /// Migration must NOT take state belonging to another room.
    ///
    /// The legacy stem is shared, so the meta's own `room` is the only thing
    /// that says whose it is. Moving it on any weaker test would hand one
    /// channel's group to another — the original bug with extra steps.
    #[test]
    fn legacy_state_for_another_room_is_left_alone() {
        let (dir, wire) = setup("migrate-other", 94, "@aria");
        {
            let mut legacy = MlsSession::open(&dir, "aria", "@priv", "@aria", &wire, true)
                .expect("session opens");
            legacy.create_group_as_creator().expect("bootstrap");
        }
        for suffix in ["mls", "pins", "kpledger", "mlsmeta"] {
            let per_room = dir.join(format!("aria.priv.{suffix}"));
            if per_room.exists() {
                fs::rename(&per_room, dir.join(format!("aria.{suffix}"))).expect("stage legacy");
            }
        }

        // A DIFFERENT room opens under the same handle.
        let other = MlsSession::open(&dir, "aria", "@other", "@aria", &wire, true)
            .expect("the other room opens");
        assert!(
            other.group.is_none(),
            "the other room must not inherit @priv's group"
        );
        assert!(
            dir.join("aria.mlsmeta").exists(),
            "@priv's legacy state is still there for @priv to claim"
        );

        // …and @priv can still claim it.
        let priv_again = MlsSession::open(&dir, "aria", "@priv", "@aria", &wire, false)
            .expect("@priv resumes");
        assert!(priv_again.group.is_some(), "@priv still has its group");
    }

    /// The public channel in the test above must also not be handed a session
    /// merely because ANOTHER channel left state under the same wire handle.
    /// `open_if_relevant` keyed `has_state` on the shared stem, so an unpinned
    /// public join inherited a session it had no business having.
    #[test]
    fn an_unrelated_channel_does_not_inherit_a_session_from_the_same_handle() {
        let (dir, wire) = setup("no-inherit", 92, "@aria");
        let mut private = MlsSession::open(&dir, "aria", "@priv", "@aria", &wire, true)
            .expect("private session opens");
        private.create_group_as_creator().expect("bootstrap");
        drop(private);

        assert!(
            MlsSession::open_if_relevant(&dir, "aria", "@pub", "@aria", &wire, false)
                .expect("no error")
                .is_none(),
            "a public channel with no state of its own gets no session"
        );
    }

    /// TEST-023 (REQ-023): the admission-path pin; `roomcfg :enc false` on a
    /// pinned channel is a refused downgrade and the session will not send.
    #[test]
    fn downgrade_refused_and_fails_closed() {
        let (dir, wire) = setup("downgrade", 81, "@aria");
        let mut session =
            MlsSession::open(&dir, "aria", "@research", "@aria", &wire, true).unwrap();
        assert!(session.encrypted(), "cap presence pins encrypted");

        let err = session
            .on_roomcfg("(roomcfg @research :enc false)")
            .unwrap_err();
        assert!(matches!(err, MlsError::Rejected(_)));
        assert!(session.downgrade_refused());

        // Fail closed: no sends, ever, in this state.
        let err = session.encrypt_outbound("(say @research :from @aria :text \"x\")");
        assert!(
            err.is_err(),
            "must refuse to send after a downgrade attempt"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// REQ-023: an encrypted session that has not yet joined the group refuses
    /// to emit content (no plaintext fallback). Crucially the refusal is
    /// [`MlsError::NotReady`], not [`MlsError::Rejected`]: membership can still
    /// arrive via a Welcome, so the caller must treat it as retryable rather
    /// than a fail-closed security decision that poisons the handle.
    #[test]
    fn no_plaintext_before_join() {
        let (dir, wire) = setup("nojoin", 82, "@aria");
        let mut session =
            MlsSession::open(&dir, "aria", "@research", "@aria", &wire, true).unwrap();
        let err = session
            .encrypt_outbound("(say @research :from @aria)")
            .unwrap_err();
        assert!(
            matches!(err, MlsError::NotReady(_)),
            "pre-membership refusal must be transient (retryable), got {err:?}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// The pin persists across restarts even when no cap is re-presented.
    #[test]
    fn mode_pin_persists() {
        let (dir, wire) = setup("pinpersist", 83, "@aria");
        {
            let _ = MlsSession::open(&dir, "aria", "@research", "@aria", &wire, true).unwrap();
        }
        let session = MlsSession::open(&dir, "aria", "@research", "@aria", &wire, false).unwrap();
        assert!(
            session.encrypted(),
            "a previously pinned channel stays pinned without the cap"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// TEST-002 + TEST-019: join_frames publishes keypub (last-resort + pool)
    /// and a verifiable idkey assertion.
    #[test]
    fn join_frames_publish_packages_and_idkey() {
        let (dir, wire) = setup("joinframes", 84, "@aria");
        let mut session =
            MlsSession::open(&dir, "aria", "@research", "@aria", &wire, true).unwrap();
        let frames = session.join_frames().unwrap();
        // SPEC-061 REQ-008 adds the fourth: with no group yet, ask whether anybody
        // signed an admission for us while we were away. There is no fifth here —
        // `self_seat_frames` stays empty until a grant actually arrives.
        assert_eq!(frames.len(), 4);
        assert!(frames[3].starts_with("(pairgrantget @research :for @aria"));
        assert!(cbcl_parser::parse(&frames[3]).is_ok(), "pairgrantget parses");
        assert!(frames[0].starts_with("(keypub @hub :last \""));
        assert!(frames[0].contains(":onetime ("));
        assert!(cbcl_parser::parse(&frames[0]).is_ok(), "keypub parses");

        // SPEC-013 IB-3: a keyready announce ("published, add me") for the owner.
        assert!(frames[2].starts_with("(keyready @research"));
        assert!(frames[2].contains(":from @aria"));
        assert!(cbcl_parser::parse(&frames[2]).is_ok(), "keyready parses");

        // The idkey frame is addressed to the room (so the hub fans it) and
        // round-trips through a peer's pin store.
        assert!(frames[1].starts_with("(idkey @research"));
        assert!(frames[1].contains(":from @aria"));
        let (peer_dir, _) = setup("joinframes-peer", 85, "@peer");
        let mut peer = PinStore::open(&peer_dir.join("peer.pins")).unwrap();
        let handle = kw_symbol(&frames[1], ":from").unwrap();
        let key = kw_bytes32(&frames[1], ":key").unwrap();
        let room = kw_symbol(&frames[1], ":room").unwrap();
        let nonce = kw_u64(&frames[1], ":nonce").unwrap_or(0);
        let sig = kw_b64(&frames[1], ":sig").unwrap();
        peer.apply_idkey(&handle, &key, &room, nonce, &sig, "@research")
            .expect("peer verifies and pins from the fanned assertion");
        assert_eq!(
            peer.pinned("@aria").unwrap().key,
            wire.verifying_key_bytes()
        );
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&peer_dir);
    }

    /// End-to-end over the wire-frame layer (TEST-001/003/005/006/010-shape):
    /// creator agent + joining agent exchange keypkg/welcome/deliver frames
    /// exactly as the hub would fan them; content round-trips encrypted; a
    /// removal with bye evidence evicts; restart resumes the group (REQ-009).
    /// SPEC-061 REQ-008 — a self-seat is not a membership until somebody says so.
    ///
    /// This is the test the shipped path did not have, and its absence is why an
    /// agent could hold a phantom epoch for hours while `hark safety-number`
    /// cheerfully printed it. Building an external Commit proves only that we can
    /// build one: RFC 9420 §14 is explicit that a joiner's own build succeeds
    /// whether or not the Commit is accepted.
    #[test]
    fn a_self_seat_is_not_a_membership_until_the_hub_echoes_it() {
        let (c_dir, c_wire) = setup("seat", 90, "@creator");
        let (a_dir, a_wire) = setup("seat", 91, "@agent");
        let mut creator =
            MlsSession::open(&c_dir, "creator", "@room", "@creator", &c_wire, true).unwrap();
        let mut agent = MlsSession::open(&a_dir, "agent", "@room", "@agent", &a_wire, true).unwrap();

        // Each pins the other from its own signed idkey assertion (REQ-019).
        let c_frames = creator.join_frames().unwrap();
        let a_frames = agent.join_frames().unwrap();
        creator.handle_frame(&a_frames[1]);
        agent.handle_frame(&c_frames[1]);
        creator.create_group_as_creator().unwrap();

        // The member that paired the agent signs its admission (REQ-008).
        let grant = super::super::group::PairingGrant::mint(
            &c_wire,
            "@creator",
            &c_wire.verifying_key_bytes(),
            "@room",
            "@agent",
            &a_wire.verifying_key_bytes(),
            u64::MAX,
        );
        let grant_json = serde_json::to_string(&grant).unwrap();
        let pairgrant = format!(
            "(pairgrant @room :for @agent :grant \"{}\" :from @creator)",
            B64.encode(grant_json)
        );
        let SessionEvent::Handled { outbound } = agent.handle_frame(&pairgrant) else {
            panic!("pairgrant handled")
        };
        assert!(
            outbound.iter().any(|f| f.starts_with("(groupinfoget @room")),
            "holding a grant, the agent asks for something to commit against: {outbound:?}"
        );

        // The hub serves a GroupInfo and the agent builds its Commit.
        let gi = creator.group_info_frame().expect("creator publishes a GroupInfo");
        let SessionEvent::Handled { outbound } = agent.handle_frame(&gi) else {
            panic!("groupinfo handled")
        };
        let commit = outbound
            .iter()
            .find(|f| f.starts_with("(deliver @room"))
            .expect("the Commit MUST go out")
            .clone();

        // THE POINT. Nothing has acknowledged that Commit, so nothing is seated.
        assert!(
            agent.group.is_none(),
            "an unacknowledged external Commit must not read as membership"
        );
        assert!(
            matches!(
                agent.encrypt_outbound("(tell @room \"hi\" :from @agent)"),
                Err(MlsError::NotReady(_))
            ),
            "and sending must refuse RETRYABLY rather than encrypt at a phantom epoch"
        );

        // The hub fans our own Commit back — the only acknowledgement this path
        // gets — and that is what seats us.
        agent.handle_frame(&commit);
        assert!(agent.group.is_some(), "the echo seats us");
        // …durably. `join_by_grant` builds into the provider without persisting,
        // and installing at the echo has no later frame to persist as a side
        // effect — so a restart here read a meta naming records that were not on
        // disk and reported `persisted group state missing`. Found on the live
        // daemon, not in review.
        drop(agent);
        let resumed =
            MlsSession::open(&a_dir, "agent", "@room", "@agent", &a_wire, true).unwrap();
        assert!(
            resumed.group.is_some(),
            "a seated agent MUST survive a restart — the meta is a pointer, and \
             writing it before its target is writing a dangling one"
        );
        let mut agent = resumed;
        assert!(
            agent.encrypt_outbound("(tell @room \"hi\" :from @agent)").is_ok(),
            "and only now may we send"
        );
    }

    /// The lost race, which is the failure that was found live: our Commit never
    /// comes back because somebody else's landed first. The agent must end up
    /// with no group AND its grant intact, so it can try again — not with a
    /// phantom group and a spent grant, which is permanent and silent.
    #[test]
    fn losing_the_ordering_race_leaves_the_grant_redeemable() {
        let (c_dir, c_wire) = setup("race", 92, "@creator");
        let (a_dir, a_wire) = setup("race", 93, "@agent");
        let mut creator =
            MlsSession::open(&c_dir, "creator", "@room", "@creator", &c_wire, true).unwrap();
        let mut agent = MlsSession::open(&a_dir, "agent", "@room", "@agent", &a_wire, true).unwrap();
        let c_frames = creator.join_frames().unwrap();
        let a_frames = agent.join_frames().unwrap();
        creator.handle_frame(&a_frames[1]);
        agent.handle_frame(&c_frames[1]);
        creator.create_group_as_creator().unwrap();

        let grant = super::super::group::PairingGrant::mint(
            &c_wire,
            "@creator",
            &c_wire.verifying_key_bytes(),
            "@room",
            "@agent",
            &a_wire.verifying_key_bytes(),
            u64::MAX,
        );
        let pairgrant = format!(
            "(pairgrant @room :for @agent :grant \"{}\" :from @creator)",
            B64.encode(serde_json::to_string(&grant).unwrap())
        );
        agent.handle_frame(&pairgrant);
        let gi = creator.group_info_frame().unwrap();
        agent.handle_frame(&gi);

        // No echo ever arrives. Everything the agent needs to try again survives.
        assert!(agent.group.is_none(), "no group");
        assert!(agent.pair_grant.is_some(), "and the grant is NOT spent");

        // A restart re-reads the grant from disk and can still act on it.
        drop(agent);
        let resumed =
            MlsSession::open(&a_dir, "agent", "@room", "@agent", &a_wire, true).unwrap();
        assert!(resumed.group.is_none());
        assert!(
            resumed.pair_grant.is_some(),
            "a grant spent on a commit nobody took would strand this agent forever"
        );
    }

    /// REQ-005 puts the epoch on the wire so a joiner can tell a fresh GroupInfo
    /// from a spent one. A GroupInfo is single-use (RFC 9420 §12.4.3.2) and every
    /// member republishes after every merged handshake, so several arrive at a
    /// joiner and the older ones are already dead. Committing against one of
    /// those is refused `WrongEpoch` by every member.
    ///
    /// Only the epoch DISPATCH is under test here — which frames start an attempt
    /// and which are ignored — so the carried `:gi` blob is the same object
    /// throughout; what varies is what the wire says about it.
    #[test]
    fn the_newest_groupinfo_wins_and_a_stale_one_is_ignored() {
        let (c_dir, c_wire) = setup("gi", 94, "@creator");
        let (a_dir, a_wire) = setup("gi", 95, "@agent");
        let mut creator =
            MlsSession::open(&c_dir, "creator", "@room", "@creator", &c_wire, true).unwrap();
        let mut agent = MlsSession::open(&a_dir, "agent", "@room", "@agent", &a_wire, true).unwrap();
        let c_frames = creator.join_frames().unwrap();
        let a_frames = agent.join_frames().unwrap();
        creator.handle_frame(&a_frames[1]);
        agent.handle_frame(&c_frames[1]);
        creator.create_group_as_creator().unwrap();

        let grant = super::super::group::PairingGrant::mint(
            &c_wire,
            "@creator",
            &c_wire.verifying_key_bytes(),
            "@room",
            "@agent",
            &a_wire.verifying_key_bytes(),
            u64::MAX,
        );
        let pairgrant = format!(
            "(pairgrant @room :for @agent :grant \"{}\" :from @creator)",
            B64.encode(serde_json::to_string(&grant).unwrap())
        );
        agent.handle_frame(&pairgrant);

        let published = creator.group_info_frame().unwrap();
        let epoch = kw_u64(&published, ":epoch").expect("a GroupInfo names its epoch");
        let at = |e: u64| published.replace(&format!(":epoch {epoch}"), &format!(":epoch {e}"));

        let SessionEvent::Handled { outbound } = agent.handle_frame(&at(epoch)) else {
            panic!("groupinfo handled")
        };
        assert!(
            outbound.iter().any(|f| f.starts_with("(deliver @room")),
            "the first GroupInfo starts an attempt"
        );

        // An OLDER republication is one we already have better than.
        let SessionEvent::Handled { outbound } = agent.handle_frame(&at(epoch.saturating_sub(1)))
        else {
            panic!("stale groupinfo handled")
        };
        assert!(
            outbound.is_empty(),
            "a stale GroupInfo must not start a second attempt: {outbound:?}"
        );

        // A NEWER one means the attempt in flight was built against an epoch the
        // room has left, so it can never be accepted. Rebuild against the newer.
        //
        // This is the direction the pre-fix code could not take at all: it had
        // already installed the group, so it returned early and sat forever on a
        // Commit nobody would take.
        let SessionEvent::Handled { outbound } = agent.handle_frame(&at(epoch + 1)) else {
            panic!("newer groupinfo handled")
        };
        assert!(
            outbound.iter().any(|f| f.starts_with("(deliver @room")),
            "a newer GroupInfo rebuilds the Commit: {outbound:?}"
        );
        assert!(
            agent.group.is_none(),
            "and none of this is membership until an echo says so"
        );
    }

    /// SPEC-061 CON-003 — the two joiner refusals are neither failures nor the
    /// same thing, and an agent that treats either as terminal never gets in.
    #[test]
    fn a_refused_seat_re_arms_and_asks_again_on_the_next_roster_change() {
        let (c_dir, c_wire) = setup("refuse", 96, "@creator");
        let (a_dir, a_wire) = setup("refuse", 97, "@agent");
        let mut creator =
            MlsSession::open(&c_dir, "creator", "@room", "@creator", &c_wire, true).unwrap();
        let mut agent = MlsSession::open(&a_dir, "agent", "@room", "@agent", &a_wire, true).unwrap();
        let c_frames = creator.join_frames().unwrap();
        let a_frames = agent.join_frames().unwrap();
        creator.handle_frame(&a_frames[1]);
        agent.handle_frame(&c_frames[1]);
        creator.create_group_as_creator().unwrap();

        let grant = super::super::group::PairingGrant::mint(
            &c_wire,
            "@creator",
            &c_wire.verifying_key_bytes(),
            "@room",
            "@agent",
            &a_wire.verifying_key_bytes(),
            u64::MAX,
        );
        let pairgrant = format!(
            "(pairgrant @room :for @agent :grant \"{}\" :from @creator)",
            B64.encode(serde_json::to_string(&grant).unwrap())
        );
        agent.handle_frame(&pairgrant);

        for slug in ["groupinfo-claimed", "no-groupinfo"] {
            let refusal = format!("(error @room \"{slug}\")");
            assert!(
                matches!(agent.handle_frame(&refusal), SessionEvent::Handled { .. }),
                "{slug} is consumed, not rendered as a chat error"
            );
            // …and the next roster change asks again. Without this the agent
            // holds an admission grant it will never present.
            let SessionEvent::Handled { outbound } =
                agent.handle_frame("(presence @room :members (@creator @agent))")
            else {
                panic!("presence handled")
            };
            assert!(
                outbound.iter().any(|f| f.starts_with("(groupinfoget @room")),
                "after {slug}, a roster change re-asks: {outbound:?}"
            );
            agent.present.clear(); // so the next loop iteration sees a fresh roster
        }
    }

    /// An error that is not ours must still reach the operator. Consuming every
    /// `(error …)` would silence the ones a person needs to see.
    #[test]
    fn an_unrelated_error_is_not_swallowed_by_the_seat_path() {
        let (a_dir, a_wire) = setup("refuse-other", 98, "@agent");
        let mut agent = MlsSession::open(&a_dir, "agent", "@room", "@agent", &a_wire, true).unwrap();
        assert!(matches!(
            agent.handle_frame("(error @room \"forbidden-room\")"),
            SessionEvent::NotMls
        ));
        assert!(
            matches!(
                agent.handle_frame("(error @other \"groupinfo-claimed\")"),
                SessionEvent::NotMls
            ),
            "another room's refusal is not ours"
        );
    }

    /// [[SPEC-013-mls-private-channels#REQ-025]] (a)/(b)/(d) — the desync
    /// self-heal. A fork is the one failure that does not mend by waiting: our
    /// epoch has parted from the room's, so every later Commit is undecryptable
    /// and every message we send is sealed to an epoch nobody is on.
    ///
    /// Before this, hark warned and kept the dead group forever. An agent was
    /// found live in exactly that state — reporting `connected`, accepting
    /// `hark emit` with exit 0, for hours.
    #[test]
    fn a_forked_group_is_discarded_and_re_admission_is_requested() {
        let (c_dir, c_wire) = setup("fork", 100, "@creator");
        let (a_dir, a_wire) = setup("fork", 101, "@agent");
        let mut creator =
            MlsSession::open(&c_dir, "creator", "@room", "@creator", &c_wire, true).unwrap();
        let mut agent = MlsSession::open(&a_dir, "agent", "@room", "@agent", &a_wire, true).unwrap();
        let c_frames = creator.join_frames().unwrap();
        let a_frames = agent.join_frames().unwrap();
        creator.handle_frame(&a_frames[1]);
        agent.handle_frame(&c_frames[1]);
        // The agent holds a group of its own to fork away from, and a grant it
        // has not spent — the state SPEC-061 REQ-008 leaves it in.
        agent.create_group_as_creator().unwrap();
        let grant = super::super::group::PairingGrant::mint(
            &c_wire,
            "@creator",
            &c_wire.verifying_key_bytes(),
            "@room",
            "@agent",
            &a_wire.verifying_key_bytes(),
            u64::MAX,
        );
        agent.pair_grant = Some(serde_json::to_string(&grant).unwrap());
        assert!(agent.group.is_some(), "precondition: we hold a group");

        // FORK_THRESHOLD consecutive undecryptable frames. Below it, a drop is
        // ordinary noise on a lossy path and must NOT tear down the group.
        let garbage = format!(
            "(deliver @room :enc mls :ct \"{}\" :from @creator)",
            B64.encode([0xAAu8; 96])
        );
        for i in 1..FORK_SIGNAL_THRESHOLD {
            let event = agent.handle_frame(&garbage);
            assert!(
                matches!(event, SessionEvent::Dropped { .. }),
                "drop {i} is noise, not a fork"
            );
            assert!(agent.group.is_some(), "and must not discard the group");
        }

        let SessionEvent::Forked { outbound, .. } = agent.handle_frame(&garbage) else {
            panic!("crossing the threshold is a fork, not another drop")
        };

        // (a) the forked group is gone…
        assert!(agent.group.is_none(), "the forked group is discarded");
        // …and the identity survives it, because the re-admission Welcome is
        // opened with exactly that key material. A whole-provider wipe here
        // would permanently brick recovery (review F8).
        assert!(
            agent.own_idkey_frame().is_ok(),
            "the identity keystore MUST survive the discard"
        );

        // (b) the request is signed, marked, and nonced.
        let resync = outbound
            .iter()
            .find(|f| f.starts_with("(keyready @room"))
            .expect("a re-admission request MUST go out");
        // An agent holding an unspent grant takes BOTH routes out. Waiting for a
        // roster change to notice it could seat itself is a stall on a quiet
        // channel, and the grant survives the discard precisely so it need not.
        assert!(
            outbound.iter().any(|f| f.starts_with("(groupinfoget @room")),
            "a grant-holding agent also asks for something to re-seat against: {outbound:?}"
        );
        assert!(
            resync.contains(":resync 1"),
            "REQ-025(d): only an explicit marker requests re-provisioning — a routine \
             re-announce must never churn membership: {resync}"
        );
        let nonce = kw_u64(resync, ":nonce").expect("a nonce");
        let sig = kw_b64(resync, ":sig").expect("a signature");
        let key = <[u8; 32]>::try_from(agent.identity.public_key()).unwrap();
        // An unsigned request is a hub-forgeable eviction of a healthy member,
        // so the verifier checks this against the requester's PINNED key.
        {
            use ed25519_dalek::{Signature, Verifier, VerifyingKey};
            let vk = VerifyingKey::from_bytes(&a_wire.verifying_key_bytes()).unwrap();
            let signed =
                super::super::pins::resync_signing_bytes(&agent.handle, &key, "@room", nonce);
            assert!(
                vk.verify(&signed, &Signature::from_slice(&sig).unwrap()).is_ok(),
                "the resync MUST verify under the requester's own PINNED wire key — \
                 an unsigned or wrongly-signed one is a hub-forgeable eviction"
            );
        }
    }

    /// [[SPEC-013-mls-private-channels#TEST-025]] positive + negative-output (F8)
    /// — the whole point of the discard being SCOPED.
    ///
    /// A forked member must recover to the live epoch after re-admission, and it
    /// can only do that if the discard left its identity keystore and its
    /// unconsumed [[KeyPackage]] init private keys alone. A whole-provider wipe
    /// looks like a tidier fix and permanently bricks recovery: the re-admission
    /// Welcome is sealed to an init key the victim no longer holds.
    ///
    /// Asserted end to end rather than by inspecting storage, because "the keys
    /// are still there" is only interesting if the Welcome actually opens.
    #[test]
    fn a_discarded_member_can_still_open_its_re_admission_welcome() {
        let (c_dir, c_wire) = setup("heal", 103, "@creator");
        let (a_dir, a_wire) = setup("heal", 104, "@agent");
        let mut creator =
            MlsSession::open(&c_dir, "creator", "@room", "@creator", &c_wire, true).unwrap();
        let mut agent = MlsSession::open(&a_dir, "agent", "@room", "@agent", &a_wire, true).unwrap();
        let c_frames = creator.join_frames().unwrap();
        let a_frames = agent.join_frames().unwrap();
        creator.handle_frame(&a_frames[1]);
        agent.handle_frame(&c_frames[1]);
        creator.create_group_as_creator().unwrap();

        // The agent's one-time packages, published BEFORE the fork. These are
        // what the re-admission Welcome will be sealed to.
        let agent_kp = match kw_value(&a_frames[0], ":onetime") {
            Some(SExpr::List(items)) => match &items[0] {
                SExpr::Atom(Atom::Str(s)) => s.clone(),
                _ => panic!("a one-time package"),
            },
            _ => panic!("a onetime list"),
        };

        // The agent holds a group and forks away from it.
        agent.create_group_as_creator().unwrap();
        let garbage = format!(
            "(deliver @room :enc mls :ct \"{}\" :from @creator)",
            B64.encode([0xAAu8; 96])
        );
        for _ in 0..FORK_SIGNAL_THRESHOLD {
            agent.handle_frame(&garbage);
        }
        assert!(agent.group.is_none(), "precondition: forked and discarded");

        // The creator honours the request by adding it at the live epoch.
        let keypkg = format!("(keypkg @hub :for @agent :kp \"{agent_kp}\")");
        let SessionEvent::Handled { outbound } = creator.handle_frame(&keypkg) else {
            panic!("keypkg handled")
        };
        let welcome = outbound
            .iter()
            .find(|f| f.starts_with("(welcome @room"))
            .expect("the re-admission Welcome");

        // F8: if the discard had wiped the provider, this is where recovery would
        // be permanently dead — the Welcome would be sealed to an init key the
        // agent no longer holds.
        agent.handle_frame(welcome);
        assert!(
            agent.group.is_some(),
            "the re-admission Welcome MUST open — a scoped discard is the whole \
             difference between recoverable and bricked (review F8)"
        );
        assert_eq!(
            agent.safety_numbers().ok().map(|s| s.epoch_state),
            creator.safety_numbers().ok().map(|s| s.epoch_state),
            "and the healed member converges on the room's epoch (REQ-021/024)"
        );
        assert_eq!(
            agent.resync_attempts, 0,
            "REQ-025(d): a successful join resets the fork counters"
        );
    }

    /// [[SPEC-013-mls-private-channels#REQ-025]](d) — recovery resets the
    /// DETECTOR, not merely the retry bookkeeping.
    ///
    /// `ForkSignal::record_success` fires only on the decrypted APPLICATION path
    /// in `process_inbound`: a processed Commit never reset it, and a
    /// re-admission Welcome does not go through `process_inbound` at all. So a
    /// recovered agent resumed still standing at the threshold, and the next
    /// single malformed frame from its own group crossed it again immediately —
    /// one bad frame and the group it had just been re-admitted to was discarded.
    #[test]
    fn recovery_resets_the_fork_detector_not_just_the_retry_counters() {
        let (c_dir, c_wire) = setup("detector", 107, "@creator");
        let (a_dir, a_wire) = setup("detector", 108, "@agent");
        let mut creator =
            MlsSession::open(&c_dir, "creator", "@room", "@creator", &c_wire, true).unwrap();
        let mut agent = MlsSession::open(&a_dir, "agent", "@room", "@agent", &a_wire, true).unwrap();
        let c_frames = creator.join_frames().unwrap();
        let a_frames = agent.join_frames().unwrap();
        creator.handle_frame(&a_frames[1]);
        agent.handle_frame(&c_frames[1]);
        creator.create_group_as_creator().unwrap();
        let agent_kp = match kw_value(&a_frames[0], ":onetime") {
            Some(SExpr::List(items)) => match &items[0] {
                SExpr::Atom(Atom::Str(s)) => s.clone(),
                _ => panic!("a one-time package"),
            },
            _ => panic!("a onetime list"),
        };

        agent.create_group_as_creator().unwrap();
        let garbage = format!(
            "(deliver @room :enc mls :ct \"{}\" :from @creator)",
            B64.encode([0xAAu8; 96])
        );
        for _ in 0..FORK_SIGNAL_THRESHOLD {
            agent.handle_frame(&garbage);
        }
        assert!(agent.group.is_none(), "forked and discarded");
        assert!(agent.fork_active(), "and reported as forked");

        // Re-admitted.
        let keypkg = format!("(keypkg @hub :for @agent :kp \"{agent_kp}\")");
        let SessionEvent::Handled { outbound } = creator.handle_frame(&keypkg) else {
            panic!("keypkg handled")
        };
        let welcome = outbound
            .iter()
            .find(|f| f.starts_with("(welcome @room"))
            .expect("the re-admission Welcome");
        agent.handle_frame(welcome);
        assert!(agent.group.is_some(), "recovered");
        assert!(
            !agent.fork_active(),
            "REQ-025(d): the join ends the fork, and the status must say so"
        );

        // THE POINT: one bad frame after recovery is noise, not a fresh fork.
        // A detector left standing at the threshold would discard here.
        match agent.handle_frame(&garbage) {
            SessionEvent::Dropped { probable_fork, .. } => assert!(
                !probable_fork,
                "a single failure after recovery must not re-cross a threshold \
                 that was never lowered"
            ),
            other => panic!("expected a plain drop, got {other:?}"),
        }
        assert!(
            agent.group.is_some(),
            "and the freshly re-admitted group must survive it"
        );
    }

    /// REQ-025(c) — exhausted recovery is TERMINAL and must be readable as such.
    ///
    /// Distinct from an active fork, and the distinction is the requirement: a
    /// fork is a condition the agent is working through, this is the admission
    /// that it cannot. Reported only through `tracing::error!`, it reached
    /// nobody — the daemon collects no logs, so an operator saw an agent
    /// indefinitely "recovering" from something it had already given up on.
    #[test]
    fn exhausted_recovery_is_distinguishable_from_an_active_fork() {
        let (a_dir, a_wire) = setup("exhausted", 109, "@agent");
        let mut agent = MlsSession::open(&a_dir, "agent", "@room", "@agent", &a_wire, true).unwrap();
        agent.create_group_as_creator().unwrap();
        let garbage = format!(
            "(deliver @room :enc mls :ct \"{}\" :from @creator)",
            B64.encode([0xAAu8; 96])
        );
        for _ in 0..FORK_SIGNAL_THRESHOLD {
            agent.handle_frame(&garbage);
        }
        assert!(agent.fork_active(), "forked");
        assert!(
            !agent.recovery_exhausted(),
            "but still trying — these are not the same state"
        );

        while !agent.resync_frames().is_empty() {}
        assert!(
            agent.recovery_exhausted(),
            "REQ-025(c): the budget is spent and that fact is queryable, not only logged"
        );
    }

    /// A frame for somebody ELSE'S group is not evidence that ours has forked.
    ///
    /// The distinction only started to matter once recovery existed to be
    /// triggered by it, which is why it survived until the fix was run against
    /// live traffic: three replayed frames carrying an old group id crossed the
    /// fork threshold, [[SPEC-013-mls-private-channels#REQ-025]] discarded a
    /// perfectly healthy group, the agent re-seated, the hub replayed again — a
    /// discard/re-seat loop that never converged. Observed on the live daemon.
    #[test]
    fn a_frame_for_another_group_never_counts_as_a_fork() {
        let (a_dir, a_wire) = setup("foreign", 105, "@agent");
        let (o_dir, o_wire) = setup("foreign", 106, "@other");
        let mut agent = MlsSession::open(&a_dir, "agent", "@room", "@agent", &a_wire, true).unwrap();
        let mut other = MlsSession::open(&o_dir, "other", "@room", "@other", &o_wire, true).unwrap();
        agent.create_group_as_creator().unwrap();
        // A DIFFERENT group for the same room name — the shape a recreated
        // channel, or a replay from before a re-seat, actually delivers.
        other.create_group_as_creator().unwrap();
        let foreign = other
            .encrypt_outbound("(tell @room \"not for you\" :from @other)")
            .expect("the other group encrypts for itself");

        // Well past the threshold: this must never accumulate.
        for i in 0..(FORK_SIGNAL_THRESHOLD * 4) {
            match agent.handle_frame(&foreign) {
                SessionEvent::Dropped { probable_fork, .. } => assert!(
                    !probable_fork,
                    "frame {i} belongs to another group and must not count toward OUR fork signal"
                ),
                other => panic!("expected a plain drop, got {other:?}"),
            }
            assert!(
                agent.group.is_some(),
                "and the healthy group must never be discarded because of it"
            );
        }
    }

    /// REQ-025(b), re-review #1 — the nonce is strictly monotonic, and it is NOT
    /// the pin epoch. The pin epoch is constant absent a rotation, so a captured
    /// resync could be replayed to evict a healthy member at will.
    ///
    /// REQ-025(c) — and the retry budget is spent on REQUESTS, not on decrypt
    /// failures. That is the F4 defect the spec names: after the discard nothing
    /// decrypts, so no failures accrue and a terminal branch keyed on them can
    /// never be reached. cbcl-bus shipped exactly that; hark SHALL NOT copy it.
    #[test]
    fn resync_nonces_rise_and_the_retry_budget_is_finite() {
        let (a_dir, a_wire) = setup("fork-cap", 102, "@agent");
        let mut agent = MlsSession::open(&a_dir, "agent", "@room", "@agent", &a_wire, true).unwrap();
        agent.create_group_as_creator().unwrap();
        let garbage = format!(
            "(deliver @room :enc mls :ct \"{}\" :from @creator)",
            B64.encode([0xAAu8; 96])
        );
        for _ in 0..FORK_SIGNAL_THRESHOLD {
            agent.handle_frame(&garbage);
        }
        assert!(agent.group.is_none(), "forked and discarded");

        let mut nonces = vec![agent.last_resync_nonce];
        // The first request was spent by the fork itself; the cap covers the run.
        let mut sent = 1;
        for _ in 0..10 {
            let frames = agent.resync_frames();
            if frames.is_empty() {
                break;
            }
            sent += 1;
            nonces.push(agent.last_resync_nonce);
        }
        assert_eq!(
            sent, RESYNC_CAP,
            "the budget is finite and reachable while groupless (REQ-025c / review F4)"
        );
        assert!(
            nonces.windows(2).all(|w| w[1] > w[0]),
            "every nonce strictly exceeds the last: {nonces:?}"
        );
        assert!(
            agent.resync_frames().is_empty(),
            "and a spent budget stays spent rather than looping"
        );
        assert!(
            agent.resync_exhausted,
            "F4: the TERMINAL surface is reached, not dead code — the shipped web \
             client keyed it on decrypt failures that stop accruing after the discard"
        );
    }

    /// Build a creator holding a group with `@peer` seated, and a signed resync
    /// request from `@peer`. Returns (creator, peer wire identity, nonce).
    fn resync_fixture(tag: &str) -> (MlsSession, ChatIdentity, PathBuf) {
        let (c_dir, c_wire) = setup(tag, 120, "@creator");
        let (p_dir, p_wire) = setup(tag, 121, "@peer");
        let mut creator =
            MlsSession::open(&c_dir, "creator", "@room", "@creator", &c_wire, true).unwrap();
        let mut peer = MlsSession::open(&p_dir, "peer", "@room", "@peer", &p_wire, true).unwrap();
        let c_frames = creator.join_frames().unwrap();
        let p_frames = peer.join_frames().unwrap();
        creator.handle_frame(&p_frames[1]);
        peer.handle_frame(&c_frames[1]);
        creator.create_group_as_creator().unwrap();
        // Seat the peer so it is a live leaf with a stale one to replace.
        let peer_kp = match kw_value(&p_frames[0], ":onetime") {
            Some(SExpr::List(items)) => match &items[0] {
                SExpr::Atom(Atom::Str(s)) => s.clone(),
                _ => panic!("a one-time package"),
            },
            _ => panic!("a onetime list"),
        };
        let SessionEvent::Handled { outbound } =
            creator.handle_frame(&format!("(keypkg @hub :for @peer :kp \"{peer_kp}\")"))
        else {
            panic!("seat the peer")
        };
        let welcome = outbound
            .iter()
            .find(|f| f.starts_with("(welcome @room"))
            .expect("welcome");
        peer.handle_frame(welcome);
        (creator, p_wire, p_dir)
    }

    fn resync_frame(wire: &ChatIdentity, handle: &str, room: &str, nonce: u64) -> String {
        let key = wire.verifying_key_bytes();
        let sig = wire.sign(&super::super::pins::resync_signing_bytes(handle, &key, room, nonce));
        format!(
            "(keyready {room} :from {handle} :resync 1 :nonce {nonce} :sig \"{}\")",
            B64.encode(sig)
        )
    }

    /// [[SPEC-013-mls-private-channels#REQ-026]] — the happy path, which did not
    /// exist: hark ignored `keyready` entirely, so a channel whose only other
    /// members were agents had no re-provisioner and a forked member could be
    /// recovered only by a human re-pairing it.
    /// A valid request from a live member is VERIFIED and then declined, because
    /// re-provisioning cannot evict safely yet (see `REPROVISIONING_MAY_EVICT`).
    ///
    /// It is still accounted for: the nonce floor rises and the budget is spent,
    /// which is what the replay and rate-limit tests below observe. A request we
    /// verified is one we have seen.
    #[test]
    fn a_valid_resync_is_verified_and_then_declined_while_eviction_is_disabled() {
        let (mut creator, p_wire, _p_dir) = resync_fixture("req026-ok");
        let before = creator.member_handles().unwrap_or_default();
        let SessionEvent::Handled { outbound } =
            creator.handle_frame(&resync_frame(&p_wire, "@peer", "@room", 1_000))
        else {
            panic!("resync handled")
        };
        assert!(
            outbound.is_empty(),
            "nothing is fetched, because fetching is the first step of an eviction \
             we cannot complete safely: {outbound:?}"
        );
        assert_eq!(
            creator.member_handles().unwrap_or_default(),
            before,
            "and the live member stays exactly where it is"
        );
        // Verified, therefore recorded: the SAME frame is now stale.
        assert_eq!(
            creator.resync_nonces.get("@peer").copied(),
            Some(1_000),
            "a verified request raises the floor even though it was declined"
        );
    }

    /// REQ-026(a)(i) — an unsigned or wrongly-signed request is not honoured, and
    /// the key it is checked against is the PINNED one. A request carrying its
    /// own key proves only that whoever wrote it holds that key, which a hub does.
    #[test]
    fn a_forged_or_unsigned_resync_evicts_nobody() {
        let (mut creator, p_wire, _p_dir) = resync_fixture("req026-forged");
        let (_o_dir, outsider) = setup("req026-forged-o", 122, "@outsider");

        // Signed by somebody else entirely.
        let forged = resync_frame(&outsider, "@peer", "@room", 1_000);
        let SessionEvent::Handled { outbound } = creator.handle_frame(&forged) else {
            panic!("handled")
        };
        assert!(outbound.is_empty(), "a forged resync fetches nothing: {outbound:?}");

        // No signature at all.
        let unsigned = "(keyready @room :from @peer :resync 1 :nonce 1000)";
        let SessionEvent::Handled { outbound } = creator.handle_frame(unsigned) else {
            panic!("handled")
        };
        assert!(outbound.is_empty(), "an unsigned resync fetches nothing: {outbound:?}");

        // …and the honest one still verifies, so the refusals above are the check
        // firing rather than the path being broken. Observed on the nonce floor,
        // which only a request that passed every check reaches.
        assert_eq!(creator.resync_nonces.get("@peer"), None, "nothing verified yet");
        creator.handle_frame(&resync_frame(&p_wire, "@peer", "@room", 1_000));
        assert_eq!(
            creator.resync_nonces.get("@peer").copied(),
            Some(1_000),
            "the genuine request verifies"
        );
    }

    /// REQ-026(a)(ii), re-review #1 — a replayed request evicts nobody.
    ///
    /// The captured frame is perfectly authentic, which is exactly why the
    /// signature cannot be the whole check: replaying it would churn a healthy
    /// member out of the group at will.
    #[test]
    fn a_replayed_resync_is_refused_even_though_it_verifies() {
        let (mut creator, p_wire, _p_dir) = resync_fixture("req026-replay");
        let frame = resync_frame(&p_wire, "@peer", "@room", 1_000);
        creator.handle_frame(&frame);
        assert_eq!(creator.resync_nonces.get("@peer").copied(), Some(1_000), "verified once");
        let spent = creator.resync_honoured.get("@peer").copied();

        // The very same bytes again: refused, and it does not spend the budget a
        // second time — a replay must cost the attacker, not the member.
        creator.handle_frame(&frame);
        assert_eq!(creator.resync_honoured.get("@peer").copied(), spent, "a replay is refused");

        // An older nonce equally: "not seen before" is not the test, "strictly
        // greater" is.
        creator.handle_frame(&resync_frame(&p_wire, "@peer", "@room", 999));
        assert_eq!(creator.resync_honoured.get("@peer").copied(), spent, "a lower nonce is refused");
        assert_eq!(creator.resync_nonces.get("@peer").copied(), Some(1_000), "the floor never falls");
    }

    /// REQ-026(d) — a routine re-announce must never churn membership, and a
    /// resync from a handle that is not a live leaf has no stale leaf to replace.
    #[test]
    fn a_routine_announce_and_a_non_member_resync_change_nothing() {
        let (mut creator, _p_wire, _p_dir) = resync_fixture("req026-routine");
        assert!(
            matches!(
                creator.handle_frame("(keyready @room :from @peer)"),
                SessionEvent::NotMls
            ),
            "a routine keyready is not a re-provisioning request"
        );
        let (_o_dir, outsider) = setup("req026-routine-o", 123, "@outsider");
        let SessionEvent::Handled { outbound } =
            creator.handle_frame(&resync_frame(&outsider, "@outsider", "@room", 1))
        else {
            panic!("handled")
        };
        assert!(
            outbound.is_empty(),
            "a non-member has no leaf to re-provision: {outbound:?}"
        );
    }

    /// REQ-026(e), re-review #2 — the rate limit is keyed on WALL-CLOCK time.
    ///
    /// Each honoured resync is itself a Remove plus an Add, so it bumps the epoch
    /// twice; an epoch-keyed window would reset on its own trigger and bound
    /// nothing at all.
    #[test]
    fn honoured_resyncs_are_rate_limited_per_member() {
        let (mut creator, p_wire, _p_dir) = resync_fixture("req026-rate");
        for i in 1..=RESYNC_RATE as u64 {
            creator.handle_frame(&resync_frame(&p_wire, "@peer", "@room", 1_000 + i));
            assert_eq!(
                creator.resync_honoured.get("@peer").map(|(_, n)| *n),
                Some(i as u32),
                "request {i} is within the budget and is counted"
            );
        }
        // Past the budget the request is refused BEFORE the nonce floor moves —
        // this is drain and churn, not recovery.
        let floor = creator.resync_nonces.get("@peer").copied();
        creator.handle_frame(&resync_frame(&p_wire, "@peer", "@room", 9_999));
        assert_eq!(
            creator.resync_nonces.get("@peer").copied(),
            floor,
            "a rate-limited request is not recorded as seen"
        );
        assert_eq!(
            creator.resync_honoured.get("@peer").map(|(_, n)| *n),
            Some(RESYNC_RATE),
            "and the budget does not grow past its cap"
        );
    }

    /// REQ-026(a)(ii)/(e) — the replay floor and the rate budget survive a
    /// restart.
    ///
    /// Held only in memory they reset on every restart, so a hub that captured
    /// one valid resync could replay it after any restart of ours and churn a
    /// healthy member. A replay window that reopens on a restart is not a replay
    /// defence — it is one that happens to be closed while nothing has gone
    /// wrong. Restarts are ordinary: a deploy, a crash, a laptop lid.
    #[test]
    fn the_resync_replay_floor_survives_a_restart() {
        let (c_dir, c_wire) = setup("req026-durable", 132, "@creator");
        let (p_dir, p_wire) = setup("req026-durable", 133, "@peer");
        let mut creator =
            MlsSession::open(&c_dir, "creator", "@room", "@creator", &c_wire, true).unwrap();
        let mut peer = MlsSession::open(&p_dir, "peer", "@room", "@peer", &p_wire, true).unwrap();
        let c_frames = creator.join_frames().unwrap();
        let p_frames = peer.join_frames().unwrap();
        creator.handle_frame(&p_frames[1]);
        peer.handle_frame(&c_frames[1]);
        creator.create_group_as_creator().unwrap();
        let peer_kp = match kw_value(&p_frames[0], ":onetime") {
            Some(SExpr::List(items)) => match &items[0] {
                SExpr::Atom(Atom::Str(s)) => s.clone(),
                _ => panic!("package"),
            },
            _ => panic!("list"),
        };
        let SessionEvent::Handled { outbound } =
            creator.handle_frame(&format!("(keypkg @hub :for @peer :kp \"{peer_kp}\")"))
        else {
            panic!("seat")
        };
        peer.handle_frame(
            outbound.iter().find(|f| f.starts_with("(welcome @room")).unwrap(),
        );

        let captured = resync_frame(&p_wire, "@peer", "@room", 4_242);
        creator.handle_frame(&captured);
        assert_eq!(
            creator.resync_nonces.get("@peer").copied(),
            Some(4_242),
            "verified once, and recorded"
        );
        drop(creator);

        // The creator restarts. The captured frame is replayed at it.
        let mut restarted =
            MlsSession::open(&c_dir, "creator", "@room", "@creator", &c_wire, true).unwrap();
        assert_eq!(
            restarted.resync_nonces.get("@peer").copied(),
            Some(4_242),
            "the floor survived the restart"
        );
        // …so the captured frame is already stale, and replaying it moves nothing.
        let budget = restarted.resync_honoured.get("@peer").copied();
        restarted.handle_frame(&captured);
        assert_eq!(
            restarted.resync_honoured.get("@peer").copied(),
            budget,
            "the replay is refused across the restart"
        );
    }

    /// NFR-001 — a hub MUST NOT be able to change who is in a group, and the
    /// KeyPackage it chooses to serve is the only input it has here.
    ///
    /// The consumed-ref ledger is keyed per (handle, ROOM); the KeyPackage
    /// directory is per handle and GLOBAL — `keyget` is addressed to `@hub` and
    /// names no room. So a package the target published from a DIFFERENT room is
    /// pin-valid, absent from this room's ledger, and its init private key lives
    /// in a provider this room's session cannot reach.
    ///
    /// Serve that on a heal and the Remove commits against a re-add the target
    /// can never open: it is evicted, the roster keeps a leaf nobody holds the
    /// key for, and the safety numbers diverge in silence.
    #[test]
    fn a_key_package_from_another_room_evicts_nobody() {
        let (c_dir, c_wire) = setup("nfr001", 140, "@creator");
        let (p_dir, p_wire) = setup("nfr001", 141, "@peer");
        let mut creator =
            MlsSession::open(&c_dir, "creator", "@rooma", "@creator", &c_wire, true).unwrap();
        let mut peer_a =
            MlsSession::open(&p_dir, "peer", "@rooma", "@peer", &p_wire, true).unwrap();
        let c_frames = creator.join_frames().unwrap();
        let a_frames = peer_a.join_frames().unwrap();
        creator.handle_frame(&a_frames[1]);
        peer_a.handle_frame(&c_frames[1]);
        creator.create_group_as_creator().unwrap();

        let pkg = |frame: &str, i: usize| match kw_value(frame, ":onetime") {
            Some(SExpr::List(items)) => match &items[i] {
                SExpr::Atom(Atom::Str(s)) => s.clone(),
                _ => panic!("package"),
            },
            _ => panic!("list"),
        };
        // Seat the peer in @rooma using one of ITS @rooma packages.
        let SessionEvent::Handled { outbound } =
            creator.handle_frame(&format!("(keypkg @hub :for @peer :kp \"{}\")", pkg(&a_frames[0], 0)))
        else {
            panic!("seat")
        };
        peer_a.handle_frame(
            outbound.iter().find(|f| f.starts_with("(welcome @rooma")).unwrap(),
        );
        assert!(peer_a.group.is_some(), "peer seated in @rooma");

        // The SAME handle also has a session in another room, with its own
        // provider and its own published packages.
        let mut peer_b =
            MlsSession::open(&p_dir, "peer", "@roomb", "@peer", &p_wire, true).unwrap();
        let b_frames = peer_b.join_frames().unwrap();
        let foreign = pkg(&b_frames[0], 0);

        creator.handle_frame(&resync_frame(&p_wire, "@peer", "@rooma", 6_000));
        let before = creator.member_handles().unwrap_or_default();

        // The hub answers @rooma's heal with a package from @roomb. Pin-valid,
        // right handle, and unopenable by the @rooma session.
        creator.handle_frame(&format!("(keypkg @hub :for @peer :kp \"{foreign}\")"));
        assert_eq!(
            creator.member_handles().unwrap_or_default(),
            before,
            "nobody is evicted — the hub does not get to remove a member by choosing \
             which of its packages to serve (NFR-001)"
        );
        assert!(
            peer_a.group.is_some(),
            "and the peer it would have stranded still holds its group"
        );
    }

    /// REQ-026(d) — a PINNED handle that is not a live leaf has no stale leaf to
    /// replace, and must not be routed into re-provisioning.
    ///
    /// The previous test for this used an unpinned handle, so it was refused at
    /// the pin lookup and never reached the liveness check it named. Deleting the
    /// check left the whole suite green.
    #[test]
    fn a_pinned_non_member_resync_is_refused_at_the_liveness_check() {
        let (mut creator, _p_wire, _p_dir) = resync_fixture("req026-live");
        let (_o_dir, o_wire) = setup("req026-live-o", 150, "@outsider");
        let o_dir2 = std::env::temp_dir().join(format!("hark-live-o2-{}", std::process::id()));
        let _ = fs::remove_dir_all(&o_dir2);
        fs::create_dir_all(&o_dir2).unwrap();
        let mut outsider =
            MlsSession::open(&o_dir2, "outsider", "@room", "@outsider", &o_wire, true).unwrap();
        let o_frames = outsider.join_frames().unwrap();
        // PINNED — its own signed idkey — but never added to the group.
        creator.handle_frame(&o_frames[1]);
        assert!(
            creator.pins.pinned("@outsider").is_some(),
            "precondition: pinned, so the pin lookup cannot be what refuses it"
        );
        assert!(
            !creator.member_handles().unwrap_or_default().iter().any(|h| h == "@outsider"),
            "precondition: not a live leaf"
        );

        creator.handle_frame(&resync_frame(&o_wire, "@outsider", "@room", 1));
        assert_eq!(
            creator.resync_nonces.get("@outsider"),
            None,
            "refused at the liveness check — nothing about it was recorded as seen"
        );
    }

    /// REQ-026(b) — a member that is neither the genesis creator nor the elected
    /// owner declines rather than half-acting.
    ///
    /// A Commit we are not entitled to make is one every peer rejects: we would
    /// evict nobody and desync ourselves.
    #[test]
    fn a_non_creator_declines_to_re_provision() {
        let (c_dir, c_wire) = setup("req026-notcreator", 151, "@creator");
        let (p_dir, p_wire) = setup("req026-notcreator", 152, "@peer");
        let mut creator =
            MlsSession::open(&c_dir, "creator", "@room", "@creator", &c_wire, true).unwrap();
        let mut peer = MlsSession::open(&p_dir, "peer", "@room", "@peer", &p_wire, true).unwrap();
        let c_frames = creator.join_frames().unwrap();
        let p_frames = peer.join_frames().unwrap();
        creator.handle_frame(&p_frames[1]);
        peer.handle_frame(&c_frames[1]);
        creator.create_group_as_creator().unwrap();
        let peer_kp = match kw_value(&p_frames[0], ":onetime") {
            Some(SExpr::List(items)) => match &items[0] {
                SExpr::Atom(Atom::Str(s)) => s.clone(),
                _ => panic!("package"),
            },
            _ => panic!("list"),
        };
        let SessionEvent::Handled { outbound } =
            creator.handle_frame(&format!("(keypkg @hub :for @peer :kp \"{peer_kp}\")"))
        else {
            panic!("seat")
        };
        peer.handle_frame(
            outbound.iter().find(|f| f.starts_with("(welcome @room")).unwrap(),
        );

        // @peer is a live member of a group it did NOT create. A resync aimed at
        // it must be declined by it, whoever signed it.
        peer.handle_frame(&resync_frame(&c_wire, "@creator", "@room", 1));
        assert_eq!(
            peer.resync_nonces.get("@creator"),
            None,
            "a non-creator records nothing and re-provisions nobody"
        );
    }

    /// A LAST-RESORT package is reusable, so an Add must not burn it.
    ///
    /// `keypackages.rs` documents its bound as the short MLS lifetime, "enforced
    /// by the primitive, not prose", and the one-time pool is republished only on
    /// connect — so once it drains the directory serves the last-resort for every
    /// subsequent Add. Marking it consumed would refuse every member addition in
    /// the channel until somebody reconnected.
    ///
    /// This is only decidable by the adder because the flag now travels ON the
    /// package. It used to be a local `bool` that changed nothing but the
    /// lifetime, so a package documented as reusable was indistinguishable from a
    /// single-use one to the party that has to decide whether to reuse it.
    #[test]
    fn an_add_burns_a_one_time_package_and_spares_the_last_resort() {
        let (c_dir, c_wire) = setup("lastresort", 155, "@creator");
        let (p_dir, p_wire) = setup("lastresort", 156, "@peer");
        let mut creator =
            MlsSession::open(&c_dir, "creator", "@room", "@creator", &c_wire, true).unwrap();
        let mut peer = MlsSession::open(&p_dir, "peer", "@room", "@peer", &p_wire, true).unwrap();
        let c_frames = creator.join_frames().unwrap();
        let p_frames = peer.join_frames().unwrap();
        creator.handle_frame(&p_frames[1]);
        peer.handle_frame(&c_frames[1]);
        creator.create_group_as_creator().unwrap();

        let ref_of = |sess: &MlsSession, b64: &str| -> String {
            let kp = validate_key_package_bytes(&sess.provider, &B64.decode(b64).unwrap()).unwrap();
            B64.encode(kp.hash_ref(sess.provider.crypto()).unwrap().as_slice())
        };
        let last = kw_symbol(&p_frames[0], ":last").expect("a last-resort package");
        let onetime = match kw_value(&p_frames[0], ":onetime") {
            Some(SExpr::List(items)) => match &items[0] {
                SExpr::Atom(Atom::Str(s)) => s.clone(),
                _ => panic!("package"),
            },
            _ => panic!("list"),
        };
        let last_ref = ref_of(&creator, &last);
        let onetime_ref = ref_of(&creator, &onetime);

        // Add with the LAST-RESORT package.
        let SessionEvent::Handled { outbound } =
            creator.handle_frame(&format!("(keypkg @hub :for @peer :kp \"{last}\")"))
        else {
            panic!("add with last-resort")
        };
        assert_eq!(outbound.len(), 2, "commit + welcome");
        assert!(
            !creator.ledger.is_consumed(&last_ref),
            "the last-resort package is NOT burned — the pool drains to it, and burning it \
             would refuse every later Add in the channel until a reconnect"
        );
        assert!(
            !creator.ledger.is_consumed(&onetime_ref),
            "and nothing else was burned either"
        );
    }

    /// The `mark_consumed` added to `add_member` — an ordinary Add refuses a
    /// package it has already spent.
    ///
    /// Before it, the ledger held only refs consumed on the JOIN path — our own
    /// packages, as a joiner — so `add_member`'s existing guard compared a
    /// target's ref against a set it could never appear in.
    #[test]
    fn an_ordinary_add_refuses_a_package_it_has_already_spent() {
        let (c_dir, c_wire) = setup("consumed-add", 153, "@creator");
        let (p_dir, p_wire) = setup("consumed-add", 154, "@peer");
        let mut creator =
            MlsSession::open(&c_dir, "creator", "@room", "@creator", &c_wire, true).unwrap();
        let mut peer = MlsSession::open(&p_dir, "peer", "@room", "@peer", &p_wire, true).unwrap();
        let c_frames = creator.join_frames().unwrap();
        let p_frames = peer.join_frames().unwrap();
        creator.handle_frame(&p_frames[1]);
        peer.handle_frame(&c_frames[1]);
        creator.create_group_as_creator().unwrap();
        let kp = match kw_value(&p_frames[0], ":onetime") {
            Some(SExpr::List(items)) => match &items[0] {
                SExpr::Atom(Atom::Str(s)) => s.clone(),
                _ => panic!("package"),
            },
            _ => panic!("list"),
        };
        let frame = format!("(keypkg @hub :for @peer :kp \"{kp}\")");
        let SessionEvent::Handled { outbound } = creator.handle_frame(&frame) else {
            panic!("first add")
        };
        assert_eq!(outbound.len(), 2, "commit + welcome");

        // Remove the member, then let the hub serve the SAME package again.
        // Without the ledger recording the first spend, this would re-add a leaf
        // whose init key the peer consumed the first time and can no longer open.
        let evidence = creator.leave_frame().ok();
        let _ = evidence;
        let event = creator.handle_frame(&frame);
        assert!(
            matches!(event, SessionEvent::Dropped { .. }),
            "a package already spent is refused: {event:?}"
        );
    }

    #[test]
    fn full_session_flow_over_frames() {
        let (a_dir, a_wire) = setup("flow", 86, "@alice");
        let (b_dir, b_wire) = setup("flow", 87, "@bob");

        let mut alice =
            MlsSession::open(&a_dir, "alice", "@research", "@alice", &a_wire, true).unwrap();
        let mut bob = MlsSession::open(&b_dir, "bob", "@research", "@bob", &b_wire, true).unwrap();

        // Both broadcast idkey on join; each pins the other (REQ-019→REQ-011).
        let a_frames = alice.join_frames().unwrap();
        let b_frames = bob.join_frames().unwrap();
        assert!(matches!(
            bob.handle_frame(&a_frames[1]),
            SessionEvent::Handled { .. }
        ));
        assert!(matches!(
            alice.handle_frame(&b_frames[1]),
            SessionEvent::Handled { .. }
        ));

        // Alice creates the room's group (operator intent).
        alice.create_group_as_creator().unwrap();

        // Presence re-broadcasts alice's idkey (bob is newly seen) AND, since
        // alice already pinned bob, prompts the owner to fetch bob's KeyPackage.
        let SessionEvent::Handled { outbound } =
            alice.handle_frame("(presence @research :members (@alice @bob))")
        else {
            panic!("presence handled")
        };
        assert!(
            outbound
                .iter()
                .any(|f| f == "(keyget @hub :for @bob :from @alice)"),
            "owner fetches the pinned, present non-member's KeyPackage: {outbound:?}"
        );
        assert!(
            outbound.iter().any(|f| f.contains(":from @alice")),
            "a newly-seen member triggers an idkey re-broadcast: {outbound:?}"
        );

        // The hub answers with bob's published package (from his keypub).
        let bob_kp_b64 = {
            // Extract the first one-time package from bob's keypub frame.
            let keypub = &b_frames[0];
            let onetime = kw_value(keypub, ":onetime").unwrap();
            match onetime {
                SExpr::List(items) => match &items[0] {
                    SExpr::Atom(Atom::Str(s)) => s.clone(),
                    _ => panic!("onetime entry"),
                },
                _ => panic!("onetime list"),
            }
        };
        let keypkg = format!("(keypkg @hub :for @bob :kp \"{bob_kp_b64}\")");
        let SessionEvent::Handled { outbound } = alice.handle_frame(&keypkg) else {
            panic!("keypkg handled")
        };
        assert_eq!(outbound.len(), 2, "commit fan + welcome");

        // Bob consumes the fanned welcome (the commit deliver predates his
        // membership and is dropped harmlessly).
        let _ = bob.handle_frame(&outbound[0]);
        assert!(matches!(
            bob.handle_frame(&outbound[1]),
            SessionEvent::Handled { .. }
        ));
        assert!(bob.joined());

        // Encrypted content round trip with REQ-018 sender enforcement.
        let deliver = alice
            .encrypt_outbound("(say @research :from @alice :text \"hello bob\")")
            .unwrap();
        assert!(deliver.starts_with("(deliver @research :enc mls :ct \""));
        match bob.handle_frame(&deliver) {
            SessionEvent::Plaintext { text, sender } => {
                assert_eq!(sender, "@alice");
                assert!(text.contains("hello bob"));
            }
            other => panic!("expected plaintext, got {other:?}"),
        }

        // Safety numbers agree across both stacks (REQ-021/REQ-024).
        let a_nums = alice.safety_numbers().unwrap();
        let b_nums = bob.safety_numbers().unwrap();
        assert_eq!(a_nums.identity, b_nums.identity);

        // Voluntary leave: bob mints bye evidence; alice removes him with it.
        let bye = bob.leave_frame().unwrap();
        let evidence_b64 = kw_b64(&bye, ":evidence").unwrap();
        let evidence: RemovalEvidence = serde_json::from_slice(&evidence_b64).unwrap();
        let remove_deliver = alice.remove_with_evidence(&evidence).unwrap();
        assert!(remove_deliver.contains(":evidence"));
        // Bob's validator merges his own removal.
        assert!(matches!(
            bob.handle_frame(&remove_deliver),
            SessionEvent::Handled { .. }
        ));

        // REQ-009: alice restarts and still decrypts the ongoing epoch.
        drop(alice);
        let mut alice2 =
            MlsSession::open(&a_dir, "alice", "@research", "@alice", &a_wire, false).unwrap();
        assert!(alice2.joined(), "group reloads from durable state");
        assert!(alice2.encrypted(), "mode pin reloads");
        let deliver2 = alice2
            .encrypt_outbound("(say @research :from @alice :text \"post-restart\")")
            .unwrap();
        assert!(deliver2.starts_with("(deliver @research"));

        // The offline REQ-024 surface reads the same state.
        let (nums, _) = offline_safety_numbers(&a_dir, "alice", "@research").unwrap();
        assert_eq!(nums.epoch, alice2.safety_numbers().unwrap().epoch);

        let _ = fs::remove_dir_all(&a_dir);
        let _ = fs::remove_dir_all(&b_dir);
    }

    /// Late-joiner ordering (the live playtest bug): the creator/owner joins
    /// AFTER the other member, so it never received that member's join-time
    /// `idkey` fan and cannot pin them. Presence must re-broadcast idkey so
    /// the peer re-announces, the owner pins them, and the Add then succeeds —
    /// without this the group can never grow past the creator over the wire.
    #[test]
    fn owner_joining_after_peer_still_adds_via_idkey_rebroadcast() {
        let (a_dir, a_wire) = setup("late", 94, "alice");
        let (b_dir, b_wire) = setup("late", 95, "bob");
        let mut alice =
            MlsSession::open(&a_dir, "alice", "@research", "@alice", &a_wire, true).unwrap();
        let mut bob = MlsSession::open(&b_dir, "bob", "@research", "@bob", &b_wire, true).unwrap();

        // Bob joins FIRST and broadcasts his idkey — but alice is not yet
        // connected, so she never sees it (the hub fans it only to present
        // members). Bob's join frames go nowhere alice can hear.
        let _b_join = bob.join_frames().unwrap();
        assert!(
            alice.pins.pinned("@bob").is_none(),
            "alice missed bob's join idkey"
        );

        // Alice joins, creates the group, and broadcasts her own idkey.
        alice.create_group_as_creator().unwrap();
        let a_join = alice.join_frames().unwrap();
        // Bob hears alice's idkey and pins her.
        assert!(matches!(
            bob.handle_frame(&a_join[1]),
            SessionEvent::Handled { .. }
        ));

        // The hub now broadcasts presence to both. Alice sees bob (new) and
        // re-broadcasts her idkey; she still can't add him (no pin yet).
        let SessionEvent::Handled { outbound: a_pres } =
            alice.handle_frame("(presence @research :members (@alice @bob))")
        else {
            panic!("presence")
        };
        assert!(
            a_pres.iter().any(|f| f.contains(":from @alice")),
            "alice re-broadcasts idkey on seeing bob"
        );
        assert!(
            !a_pres.iter().any(|f| f.starts_with("(keyget")),
            "alice cannot keyget bob yet — no pin"
        );

        // Bob sees presence too; bob (new owner-perspective aside) re-broadcasts
        // his idkey, which is the frame alice was missing.
        let SessionEvent::Handled { outbound: b_pres } =
            bob.handle_frame("(presence @research :members (@alice @bob))")
        else {
            panic!("presence")
        };
        let bob_idkey = b_pres
            .iter()
            .find(|f| f.contains(":from @bob"))
            .expect("bob re-broadcasts his idkey on seeing alice");

        // Alice receives bob's re-broadcast idkey → pins him → and because she
        // is the owner and bob is present, immediately emits the keyget.
        let SessionEvent::Handled {
            outbound: after_pin,
        } = alice.handle_frame(bob_idkey)
        else {
            panic!("idkey handled")
        };
        assert!(alice.pins.pinned("@bob").is_some(), "alice now pins bob");
        assert!(
            after_pin
                .iter()
                .any(|f| f == "(keyget @hub :for @bob :from @alice)"),
            "pinning bob unblocks the keyget: {after_pin:?}"
        );

        // Hub answers the keyget with bob's published one-time package.
        let onetime = kw_value(&_b_join[0], ":onetime").unwrap();
        let bob_kp_b64 = match onetime {
            SExpr::List(items) => match &items[0] {
                SExpr::Atom(Atom::Str(s)) => s.clone(),
                _ => panic!("onetime entry"),
            },
            _ => panic!("onetime list"),
        };
        let SessionEvent::Handled { outbound: add_out } =
            alice.handle_frame(&format!("(keypkg @hub :for @bob :kp \"{bob_kp_b64}\")"))
        else {
            panic!("keypkg handled")
        };
        assert_eq!(add_out.len(), 2, "commit + welcome — the Add succeeded");

        // Bob joins via the welcome; both now agree on a 2-member group.
        let _ = bob.handle_frame(&add_out[0]);
        assert!(matches!(
            bob.handle_frame(&add_out[1]),
            SessionEvent::Handled { .. }
        ));
        assert!(bob.joined());
        assert_eq!(
            alice.safety_numbers().unwrap().identity,
            bob.safety_numbers().unwrap().identity,
            "both stacks agree on the membership safety number"
        );

        let _ = fs::remove_dir_all(&a_dir);
        let _ = fs::remove_dir_all(&b_dir);
    }
}
