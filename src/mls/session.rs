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
    GenesisAssertion, GenesisTrust, add_member, create_group, is_owner, join_by_grant,
    join_from_welcome,
};
use super::keypackages::{ConsumedLedger, ONE_TIME_POOL_TARGET, build_last_resort, build_one_time};
use super::pins::{PinStore, idkey_signing_bytes};
use super::provider::DurableProvider;
use super::removal::{RemovalEvidence, remove_member};
use super::safety::{SafetyNumbers, group_safety_numbers};
use super::validation::{ForkSignal, Inbound, encrypt_message, enforce_sender, process_inbound};
use super::{MlsError, MlsIdentity};
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
}

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
const STATE_SUFFIXES: [&str; 4] = ["mls", "pins", "kpledger", "mlsmeta"];

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
        let ledger = ConsumedLedger::open(&identity_dir.join(format!("{stem}.kpledger")))?;
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
        };

        if let Some(meta) = meta {
            session.enc_pinned = session.enc_pinned || meta.enc_pinned;
            session.is_v1 = meta.protocol_version >= 1;
            session.genesis = meta.genesis;
            session.pair_grant = meta.pair_grant;
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
            }) => SessionEvent::Dropped {
                reason,
                probable_fork,
            },
            Err(e) => SessionEvent::Dropped {
                reason: e.to_string(),
                probable_fork: self.fork.probable_fork(),
            },
        }
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
            let outcome = add_member(
                &self.provider,
                &self.identity,
                group,
                &kp,
                &target,
                &self.pins,
                &self.ledger,
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
