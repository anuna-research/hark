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
    GenesisAssertion, GenesisTrust, create_group, is_owner, join_from_welcome,
    merge_staged_commit, stage_add_member,
};
use super::keypackages::{
    ConsumedLedger, LAST_RESORT_LIFETIME_SECS, ONE_TIME_POOL_TARGET, build_last_resort,
    build_one_time,
};
use super::pins::{PinStore, idkey_signing_bytes};
use super::provider::DurableProvider;
use super::removal::{RemovalEvidence, stage_remove_member};
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
    /// Transition frames (Commit/Welcome) this member authored that peers may
    /// not have received (see [`MlsSession::pending_rebroadcast`]). Persisted
    /// in the same atomic meta write as the rest of the resume state, so a
    /// daemon restart after the merge does not lose the only copy of a
    /// transition nothing can regenerate.
    #[serde(default)]
    pending_broadcast: Vec<PendingBroadcast>,
}

/// One transition frame retained for re-driving, tagged with the group id
/// and the epoch right after its merge. The tags are the retention rule: a
/// frame is worth re-fanning only while the SAME group is STILL at that
/// epoch — once any later commit lands, a straggler replaying it would end
/// up behind the group anyway (recovery then needs a remove + re-add), and
/// after a group replacement (provider-loss recovery) an old-group Welcome
/// would seat its target in an obsolete group and mask the current one.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct PendingBroadcast {
    epoch: u64,
    /// The minting group's id (base64). `serde(default)` fails safe: entries
    /// persisted before this field existed load unbound and never match.
    #[serde(default)]
    group_id_b64: String,
    frame: String,
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
    /// The wire identity (signs idkey/bye assertions — same key as the MLS
    /// leaf, different DS labels).
    wire_seed: [u8; 32],
    /// The room roster from the last `presence` frame. Tracked so that when a
    /// NEW handle appears we re-broadcast our own `idkey` (REQ-019) — the
    /// hub fans an `idkey` only once at join, to then-connected members, so a
    /// late joiner would otherwise never receive an earlier member's key and
    /// could not pin it for the REQ-008 adder check.
    present: std::collections::HashSet<String>,
    /// The KeyPackage publication set most recently built by [`join_frames`],
    /// memoized so a retried rejoin republishes the SAME bundles instead of
    /// durably minting a fresh last-resort + one-time pool on every attempt.
    published: Option<PublishedKeyPackages>,
    /// Authored transition frames retained for re-driving (see
    /// [`PendingBroadcast`] and [`Self::pending_rebroadcast`]).
    pending_broadcast: Vec<PendingBroadcast>,
}

/// A memoized `keypub` publication (see [`MlsSession::join_frames`]): the
/// frame to (re)send, the refs it advertises (for consumed-ledger checks),
/// and when it was built (for the last-resort lifetime bound).
struct PublishedKeyPackages {
    keypub_frame: String,
    refs: Vec<String>,
    built_at: std::time::SystemTime,
    /// Whether the keypub frame has reached the wire. The hub's directory
    /// APPENDS `:onetime` packages on every publish (it does not dedupe), so
    /// replaying the same frame across retries would queue duplicate refs —
    /// a later keyget could then serve an already-consumed package and the
    /// resulting Welcome would fail. Once delivered, a rejoin re-sends only
    /// idkey/keyready.
    delivered: bool,
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
        let provider = DurableProvider::open(&identity_dir.join(format!("{file_stem}.mls")))?;
        let pins = PinStore::open(&identity_dir.join(format!("{file_stem}.pins")))?;
        let ledger = ConsumedLedger::open(&identity_dir.join(format!("{file_stem}.kpledger")))?;
        let meta_path = identity_dir.join(format!("{file_stem}.mlsmeta"));

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
            wire_seed: wire.signing_seed(),
            present: std::collections::HashSet::new(),
            published: None,
            pending_broadcast: Vec::new(),
        };

        if let Some(meta) = meta {
            session.enc_pinned = session.enc_pinned || meta.enc_pinned;
            session.genesis = meta.genesis;
            session.pending_broadcast = meta.pending_broadcast;
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
        // Reload prune (crash recovery): an entry AHEAD of the reloaded
        // epoch is the write-ahead of a merge that never became durable —
        // the transition never happened, and if an unrelated commit later
        // advanced the group to that epoch, the aborted Welcome would seat
        // its target in an alternate tree. Entries behind the epoch, from
        // another group, or with no group loaded are equally dead.
        session.prune_write_aheads();
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
        let has_state = identity_dir.join(format!("{file_stem}.mlsmeta")).exists();
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
            pending_broadcast: self.pending_broadcast.clone(),
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
    ///
    /// The publication set is memoized: every `build_*` call durably stores a
    /// bundle (init key) in the provider, so a reconnect loop that re-ran the
    /// builders on each attempt would grow the MLS state file without bound
    /// under retried failures. The set is rebuilt only when a ref HAS been
    /// consumed (a Welcome used one — replenishment, REQ-022) or the
    /// last-resort package is past half its lifetime (so we never advertise
    /// one the primitive would reject at add time, REQ-022's bound). The
    /// keypub frame itself is included only until [`Self::keypub_delivered`]
    /// reports it reached the wire — the hub's directory appends `:onetime`
    /// entries per publish, so replaying it would queue duplicate refs.
    pub fn join_frames(&mut self) -> Result<Vec<String>, MlsError> {
        if !self.enc_pinned {
            return Ok(Vec::new());
        }
        let reusable = self.published.as_ref().is_some_and(|set| {
            let fresh = set
                .built_at
                .elapsed()
                .is_ok_and(|age| age.as_secs() < LAST_RESORT_LIFETIME_SECS / 2);
            fresh && !set.refs.iter().any(|r| self.ledger.is_consumed(r))
        });
        if !reusable {
            let last = build_last_resort(&self.provider, &self.identity)?;
            let one_time = build_one_time(&self.provider, &self.identity, ONE_TIME_POOL_TARGET)?;
            let onetime_list = one_time
                .iter()
                .map(|p| format!("\"{}\"", B64.encode(&p.bytes)))
                .collect::<Vec<_>>()
                .join(" ");
            let keypub_frame = format!(
                "(keypub @hub :last \"{}\" :onetime ({}) :from {})",
                B64.encode(&last.bytes),
                onetime_list,
                self.handle
            );
            let refs = std::iter::once(last.ref_b64)
                .chain(one_time.into_iter().map(|p| p.ref_b64))
                .collect();
            self.published = Some(PublishedKeyPackages {
                keypub_frame,
                refs,
                built_at: std::time::SystemTime::now(),
                delivered: false,
            });
        }
        let set = self.published.as_ref().expect("publication set built above");

        let mut frames = Vec::new();
        if !set.delivered {
            frames.push(set.keypub_frame.clone());
        }
        frames.push(self.own_idkey_frame()?);
        // SPEC-013 IB-3: announce "published, add me" so a web owner has an
        // explicit, re-drivable add trigger (not just presence timing).
        frames.push(self.keyready_frame());
        // Re-drive any transition frames peers may have missed: the hub fans
        // only to currently joined sockets (encrypted joins get no backfill),
        // so a hub-wide drop where WE reconnect first would otherwise leave
        // later-returning members at the old epoch — and a local write is no
        // proof of fan-out, so these were never dequeued on send.
        frames.extend(self.pending_rebroadcast());
        // A rejoin means the hub restarted or dropped us: presence knowledge
        // is stale, so forget it — the next presence fan then treats every
        // member as newly seen, re-running the idkey/keyready/pending
        // delivery-gap logic for peers that reconnect after us.
        self.present.clear();
        Ok(frames)
    }

    /// The retained transition frames still worth re-fanning: those minted
    /// by the CURRENT group at its CURRENT epoch. Replay is inert for
    /// members already there (epoch-mismatch drop; a replayed Welcome is made
    /// inert by the consumed-ref ledger, REQ-013) and exactly what a member
    /// that missed the fan needs. Entries behind the current epoch — or from
    /// another (replaced/aborted) group, or held while no group is loaded —
    /// are never emitted: a straggler that far back cannot be healed by
    /// replay, and an old-group Welcome would seat its target in an obsolete
    /// group.
    fn pending_rebroadcast(&self) -> Vec<String> {
        let Some(group) = self.group.as_ref() else {
            return Vec::new();
        };
        let epoch = group.epoch().as_u64();
        let group_id_b64 = B64.encode(group.group_id().as_slice());
        self.pending_broadcast
            .iter()
            .filter(|p| p.epoch == epoch && p.group_id_b64 == group_id_b64)
            .map(|p| p.frame.clone())
            .collect()
    }

    /// Write-ahead one authored transition batch, APPENDING to (never
    /// clearing) the retained set: until the new merge is durable, the
    /// previous batch may still be the only Commit/Welcome able to heal a
    /// peer left at the current epoch, so it must survive the write-ahead
    /// window. Only entries already at this exact (epoch, group) — residue
    /// of an earlier aborted attempt at the same transition — are replaced.
    /// Callers persist via `persist_meta` right after.
    fn record_write_ahead(&mut self, epoch: u64, group_id_b64: &str, frames: &[String]) {
        self.pending_broadcast
            .retain(|p| !(p.epoch == epoch && p.group_id_b64 == group_id_b64));
        self.pending_broadcast
            .extend(frames.iter().map(|frame| PendingBroadcast {
                epoch,
                group_id_b64: group_id_b64.to_owned(),
                frame: frame.clone(),
            }));
    }

    /// Drop the write-ahead batch of a transition whose merge FAILED: the
    /// staged commit died with the attempt, so its frames must not lie in
    /// wait — an unrelated commit could later advance the same group to that
    /// epoch, at which point the aborted Welcome would seat its target in an
    /// alternate tree (a manufactured fork).
    fn discard_write_ahead(&mut self, epoch: u64, group_id_b64: &str) {
        self.pending_broadcast
            .retain(|p| !(p.epoch == epoch && p.group_id_b64 == group_id_b64));
    }

    /// Keep only the entries that match the group's durable state — called
    /// AFTER a merge persists (superseded batches can no longer heal anyone)
    /// and on session open (an entry AHEAD of the reloaded epoch is an
    /// aborted write-ahead whose merge never became durable; with no group
    /// loaded, nothing retained can ever be validly replayed).
    fn prune_write_aheads(&mut self) {
        let Some(group) = self.group.as_ref() else {
            self.pending_broadcast.clear();
            return;
        };
        let epoch = group.epoch().as_u64();
        let group_id_b64 = B64.encode(group.group_id().as_slice());
        self.pending_broadcast
            .retain(|p| p.epoch == epoch && p.group_id_b64 == group_id_b64);
    }

    /// The caller reports the current keypub frame reached the wire, so later
    /// [`Self::join_frames`] calls stop replaying it into the hub's
    /// append-only `:onetime` queue. Wire delivery is the best signal the
    /// client has for "the hub processed it" — the residual mismatch (a hub
    /// that died between read and store) errs on under- rather than
    /// over-publication against a durable directory.
    pub fn keypub_delivered(&mut self) {
        if let Some(set) = self.published.as_mut() {
            set.delivered = true;
        }
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
                SessionEvent::Handled { outbound: vec![] }
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
            // Stage — do NOT merge yet. Once the merge persists, these frames
            // are the only copy able to advance peers past the old epoch, so
            // they must be durable FIRST (write-ahead): a crash between the
            // meta write and the merge loses only an unsent staged commit,
            // while the reverse order would strand every peer at the old
            // epoch with nothing to replay.
            let outcome = stage_add_member(
                &self.provider,
                &self.identity,
                group,
                &kp,
                &target,
                &self.pins,
                &self.ledger,
            )?;
            // Tagged with the POST-merge epoch and the group id, so entries
            // from an aborted merge (group still behind) or an abandoned
            // group (provider-loss recovery) can never pass the replay
            // filter.
            let epoch = group.epoch().as_u64() + 1;
            let group_id_b64 = B64.encode(group.group_id().as_slice());
            let frames = vec![
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
            ];
            self.record_write_ahead(epoch, &group_id_b64, &frames);
            self.persist_meta()?;
            let group = self.group.as_mut().expect("staged above");
            if let Err(error) = merge_staged_commit(&self.provider, group, "merge own add commit")
            {
                // The transition never became durable: discard its
                // write-ahead so it cannot replay into a fork later.
                self.discard_write_ahead(epoch, &group_id_b64);
                let _ = self.persist_meta();
                return Err(error);
            }
            // Durable: batches behind the new epoch can no longer heal
            // anyone — this keeps exactly the batch just merged.
            self.prune_write_aheads();
            self.persist_meta()?;
            Ok(frames)
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
        // REPLACE the tracked roster, never accumulate: the hub derives
        // presence from live connection processes and rebroadcasts the FULL
        // roster on joins and leaves alike, so a handle absent from this
        // frame has disconnected. Keeping departed handles in the set would
        // make their eventual return invisible (`saw_new` false) and skip
        // exactly the idkey/keyready/pending re-drives a returning member
        // needs — e.g. an invitee that dropped before its Welcome arrived.
        self.present = roster.into_iter().collect();

        let mut outbound = Vec::new();
        if saw_new {
            if let Ok(frame) = self.own_idkey_frame() {
                outbound.push(frame);
            }
            // Re-broadcast the keyready trigger too (SPEC-013 IB-3), so an owner
            // that elects/joins after us gets an explicit, re-drivable add signal
            // — the same delivery-gap fix as the idkey re-broadcast above.
            outbound.push(self.keyready_frame());
            // Re-drive retained transition frames: a member (re)appearing may
            // have missed the Commit/Welcome fan (encrypted joins get no
            // backfill). Inert for anyone already at the epoch.
            outbound.extend(self.pending_rebroadcast());
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
        // Same write-ahead split as the Add path (see `on_keypkg`): stage,
        // durably retain the frame, THEN merge.
        let commit = stage_remove_member(
            &self.provider,
            &self.identity,
            group,
            &self.room,
            evidence,
            &self.pins,
            &creator,
        )?;
        let epoch = group.epoch().as_u64() + 1;
        let group_id_b64 = B64.encode(group.group_id().as_slice());
        let json = serde_json::to_vec(evidence).map_err(std::io::Error::other)?;
        let frame = format!(
            "(deliver {} :enc mls :ct \"{}\" :evidence \"{}\" :from {})",
            self.room,
            B64.encode(&commit),
            B64.encode(json),
            self.handle
        );
        self.record_write_ahead(epoch, &group_id_b64, std::slice::from_ref(&frame));
        self.persist_meta()?;
        let group = self.group.as_mut().expect("staged above");
        if let Err(error) = merge_staged_commit(&self.provider, group, "merge remove commit") {
            self.discard_write_ahead(epoch, &group_id_b64);
            let _ = self.persist_meta();
            return Err(error);
        }
        self.prune_write_aheads();
        self.persist_meta()?;
        Ok(frame)
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
    let meta_path = identity_dir.join(format!("{file_stem}.mlsmeta"));
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
    let provider = DurableProvider::open(&identity_dir.join(format!("{file_stem}.mls")))?;
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
        assert_eq!(frames.len(), 3);
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

    /// A retried rejoin must NOT durably mint a fresh KeyPackage set per
    /// attempt (`join_frames` memoizes the publication until a ref is
    /// consumed or the last-resort nears expiry), and must NOT replay a
    /// delivered keypub into the hub's append-only `:onetime` queue.
    #[test]
    fn join_frames_reuses_publication_across_retries() {
        let (dir, wire) = setup("joinreuse", 88, "@aria");
        let mut session =
            MlsSession::open(&dir, "aria", "@research", "@aria", &wire, true).unwrap();
        let first = session.join_frames().unwrap();
        assert!(first[0].starts_with("(keypub "));
        let provider_size = fs::read(dir.join("aria.mls")).unwrap().len();

        // The keypub never reached the wire: the retry re-sends the SAME
        // frame (same bundles — no provider growth).
        let retry = session.join_frames().unwrap();
        assert_eq!(
            first[0], retry[0],
            "an undelivered keypub is republished verbatim"
        );
        assert_eq!(
            fs::read(dir.join("aria.mls")).unwrap().len(),
            provider_size,
            "a retried join_frames must not grow the durable MLS state"
        );

        // Once delivered, a rejoin sends only idkey + keyready — the hub
        // APPENDS :onetime entries per publish, so a replay would queue
        // duplicate refs a keyget could serve after consumption.
        session.keypub_delivered();
        let after = session.join_frames().unwrap();
        assert_eq!(after.len(), 2, "delivered keypub is not replayed");
        assert!(after[0].starts_with("(idkey "));
        assert!(after[1].starts_with("(keyready "));
        assert_eq!(
            fs::read(dir.join("aria.mls")).unwrap().len(),
            provider_size,
            "reuse after delivery must not grow the durable MLS state either"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// A hub-wide drop can reconnect the committer BEFORE its peers, and
    /// encrypted joins get no backfill — so authored Commit/Welcome frames
    /// are never dequeued on a local write: they are re-driven on every
    /// rejoin and on peer reappearance, survive a daemon restart (persisted
    /// with the meta), still seat the stranded member, and are pruned once
    /// the epoch moves past them (replay could no longer heal a straggler).
    #[test]
    fn pending_transitions_redriven_survive_restart_and_prune_on_epoch() {
        let (a_dir, a_wire) = setup("pending", 96, "@alice");
        let (b_dir, b_wire) = setup("pending", 97, "@bob");
        let mut alice =
            MlsSession::open(&a_dir, "alice", "@research", "@alice", &a_wire, true).unwrap();
        let mut bob = MlsSession::open(&b_dir, "bob", "@research", "@bob", &b_wire, true).unwrap();

        // Standard add flow up to the commit: pins exchanged, alice owns the
        // group, the hub answers her keyget with bob's package.
        let a_frames = alice.join_frames().unwrap();
        let b_frames = bob.join_frames().unwrap();
        let _ = bob.handle_frame(&a_frames[1]);
        let _ = alice.handle_frame(&b_frames[1]);
        alice.create_group_as_creator().unwrap();
        let presence = "(presence @research :members (@alice @bob))";
        let _ = alice.handle_frame(presence);
        let bob_kp_b64 = {
            let onetime = kw_value(&b_frames[0], ":onetime").unwrap();
            match onetime {
                SExpr::List(items) => match &items[0] {
                    SExpr::Atom(Atom::Str(s)) => s.clone(),
                    _ => panic!("onetime entry"),
                },
                _ => panic!("onetime list"),
            }
        };
        let SessionEvent::Handled { outbound } =
            alice.handle_frame(&format!("(keypkg @hub :for @bob :kp \"{bob_kp_b64}\")"))
        else {
            panic!("keypkg handled")
        };
        assert_eq!(outbound.len(), 2, "commit fan + welcome");
        // Simulate the hub-wide drop: bob NEVER receives this fan.

        // A rejoin re-drives the retained transition.
        alice.keypub_delivered();
        let rejoin = alice.join_frames().unwrap();
        assert!(
            rejoin.iter().any(|f| f.starts_with("(deliver @research")),
            "rejoin re-drives the commit: {rejoin:?}"
        );
        assert!(
            rejoin.iter().any(|f| f.starts_with("(welcome @research")),
            "rejoin re-drives the welcome: {rejoin:?}"
        );

        // The rejoin reset presence knowledge, so bob REAPPEARING (same
        // roster as before) re-drives the transition again.
        let SessionEvent::Handled { outbound: redriven } = alice.handle_frame(presence) else {
            panic!("presence handled")
        };
        assert!(
            redriven.iter().any(|f| f.starts_with("(welcome @research")),
            "a reappearing peer re-drives the transition: {redriven:?}"
        );

        // DEPARTURE tracking: bob drops (roster omits him) and returns while
        // alice stays connected — the return must count as newly seen and
        // re-drive, or a member that disconnected before its Welcome arrived
        // stays stranded until some unrelated event.
        let _ = alice.handle_frame("(presence @research :members (@alice))");
        let SessionEvent::Handled { outbound: returned } = alice.handle_frame(presence) else {
            panic!("presence handled")
        };
        assert!(
            returned.iter().any(|f| f.starts_with("(welcome @research")),
            "a departed-and-returned peer re-drives the transition: {returned:?}"
        );

        // A daemon restart reloads the pending set from the durable meta.
        drop(alice);
        let mut alice2 =
            MlsSession::open(&a_dir, "alice", "@research", "@alice", &a_wire, false).unwrap();
        let rejoin2 = alice2.join_frames().unwrap();
        let welcome = rejoin2
            .iter()
            .find(|f| f.starts_with("(welcome @research"))
            .expect("pending welcome survives restart")
            .clone();

        // The re-driven welcome is exactly what seats the stranded member.
        assert!(matches!(
            bob.handle_frame(&welcome),
            SessionEvent::Handled { .. }
        ));
        assert!(bob.joined(), "the replayed welcome heals the stranded add");

        // FORK-SIGNAL immunity: the re-driven commit reaches bob (now at the
        // post-add epoch) as an old-epoch frame. Three intentional replays
        // must NOT trip a false probable-fork warning.
        let commit_deliver = rejoin2
            .iter()
            .find(|f| f.starts_with("(deliver @research"))
            .expect("pending commit survives restart")
            .clone();
        for _ in 0..3 {
            match bob.handle_frame(&commit_deliver) {
                SessionEvent::Dropped { probable_fork, .. } => {
                    assert!(
                        !probable_fork,
                        "intentional replays must not feed the fork counter"
                    );
                }
                other => panic!("expected benign drop, got {other:?}"),
            }
        }

        // (Minted while bob is still a member, for the divergence check
        // below: a valid epoch-1 application ciphertext.)
        let bob_msg = bob
            .encrypt_outbound("(say @research :from @bob :text \"divergent\")")
            .unwrap();

        // An epoch advance (bob's evidenced removal) prunes the stale add —
        // only the removal commit remains re-drivable.
        let bye = bob.leave_frame().unwrap();
        let evidence: RemovalEvidence =
            serde_json::from_slice(&kw_b64(&bye, ":evidence").unwrap()).unwrap();
        let remove_deliver = alice2.remove_with_evidence(&evidence).unwrap();
        let rejoin3 = alice2.join_frames().unwrap();
        assert!(
            !rejoin3.iter().any(|f| f.starts_with("(welcome ")),
            "the superseded welcome is pruned: {rejoin3:?}"
        );
        assert!(
            rejoin3.iter().any(|f| f == &remove_deliver),
            "the removal commit is retained: {rejoin3:?}"
        );

        // DIVERGENCE evidence: bob's valid epoch-1 application ciphertext
        // arriving at alice (now epoch 2) is NOT a duplicate — it is a
        // member sending from divergent state, and unlike the handshake
        // replays above it MUST feed the REQ-006 fork counter.
        for attempt in 1..=3u32 {
            match alice2.handle_frame(&bob_msg) {
                SessionEvent::Dropped { probable_fork, .. } => {
                    assert_eq!(
                        probable_fork,
                        attempt >= 3,
                        "past-epoch application traffic must count toward the fork signal"
                    );
                }
                other => panic!("expected counted drop, got {other:?}"),
            }
        }

        // GROUP binding: an entry from another group never passes the replay
        // filter, even at a matching epoch — the provider-loss recovery path
        // can replace the group, and an old-group Welcome would seat its
        // target in the obsolete group.
        let epoch_now = alice2.safety_numbers().unwrap().epoch;
        let real_gid = B64.encode(
            alice2
                .group
                .as_ref()
                .expect("alice2 joined")
                .group_id()
                .as_slice(),
        );
        alice2.pending_broadcast = vec![PendingBroadcast {
            epoch: epoch_now,
            group_id_b64: "bm90LXRoaXMtZ3JvdXA=".into(),
            frame: "(welcome @research :for @bob :ct \"stale\" :from @alice)".into(),
        }];
        assert!(
            alice2.pending_rebroadcast().is_empty(),
            "frames minted by a replaced group are never re-driven"
        );

        // RELOAD prune: a future-epoch entry (the write-ahead of a merge
        // that never became durable) is discarded when the session reopens —
        // it must not lie in wait for an unrelated commit to reach that
        // epoch and then seat its Welcome target in an alternate tree.
        alice2.pending_broadcast = vec![PendingBroadcast {
            epoch: epoch_now + 1,
            group_id_b64: real_gid,
            frame: "(welcome @research :for @bob :ct \"aborted\" :from @alice)".into(),
        }];
        alice2.persist_meta().unwrap();
        drop(alice2);
        let alice3 =
            MlsSession::open(&a_dir, "alice", "@research", "@alice", &a_wire, false).unwrap();
        assert!(
            alice3.pending_broadcast.is_empty(),
            "an aborted future-epoch write-ahead is pruned on reload"
        );

        let _ = fs::remove_dir_all(&a_dir);
        let _ = fs::remove_dir_all(&b_dir);
    }

    /// End-to-end over the wire-frame layer (TEST-001/003/005/006/010-shape):
    /// creator agent + joining agent exchange keypkg/welcome/deliver frames
    /// exactly as the hub would fan them; content round-trips encrypted; a
    /// removal with bye evidence evicts; restart resumes the group (REQ-009).
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
