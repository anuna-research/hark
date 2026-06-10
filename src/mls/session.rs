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
use std::path::{Path, PathBuf};

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use cbcl_core::sexpr::{Atom, SExpr};
use openmls::prelude::MlsGroup;
use openmls::group::GroupId;
use rand::Rng as _;

use super::group::{
    GenesisAssertion, GenesisTrust, add_member, create_group, is_owner, join_from_welcome,
};
use super::keypackages::{
    ConsumedLedger, ONE_TIME_POOL_TARGET, build_last_resort, build_one_time,
};
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
            Ok(bytes) => serde_json::from_slice(&bytes).ok().filter(
                |m: &SessionMeta| m.version == META_VERSION && m.room == room,
            ),
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
        };

        if let Some(meta) = meta {
            session.enc_pinned = session.enc_pinned || meta.enc_pinned;
            session.genesis = meta.genesis;
            // Reload the persisted group (REQ-009): a missing/stale state
            // simply means re-join (logged by the provider open path).
            if let Some(group_id_b64) = meta.group_id_b64 {
                if let Ok(group_id) = B64.decode(&group_id_b64) {
                    use openmls_traits::OpenMlsProvider as _;
                    session.group = MlsGroup::load(
                        session.provider.storage(),
                        &GroupId::from_slice(&group_id),
                    )
                    .ok()
                    .flatten();
                    if session.group.is_some() && session.genesis.is_some() {
                        // Trust was graded at join; a pinned creator key can
                        // only have improved since (rotations re-pin).
                        session.trust = Some(GenesisTrust::Authoritative);
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
        };
        let bytes = serde_json::to_vec(&meta).map_err(std::io::Error::other)?;
        if let Some(parent) = self.meta_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&self.meta_path, bytes)?;
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

        let key = <[u8; 32]>::try_from(self.identity.public_key())
            .map_err(|_| MlsError::Rejected("identity key is not 32 bytes".into()))?;
        let nonce: u64 = self
            .pins
            .pinned(&self.handle)
            .map(|p| p.pin_epoch)
            .unwrap_or(0);
        let wire = ChatIdentity::from_seed(self.wire_seed);
        let sig = wire.sign(&idkey_signing_bytes(&self.handle, &key, &self.room, nonce));
        frames.push(format!(
            "(idkey {} :key \"{}\" :room {} :nonce {} :sig \"{}\")",
            self.handle,
            B64.encode(key),
            self.room,
            nonce,
            B64.encode(sig)
        ));
        Ok(frames)
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
            MlsError::Rejected(format!(
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

    /// REQ-019: verify and pin from a fanned `idkey` assertion.
    fn on_idkey(&mut self, text: &str) -> SessionEvent {
        let result = (|| -> Result<(), MlsError> {
            let handle = head_target(text)
                .ok_or_else(|| MlsError::Rejected("idkey missing handle".into()))?;
            let key = kw_bytes32(text, ":key")
                .ok_or_else(|| MlsError::Rejected("idkey missing :key".into()))?;
            let room = kw_symbol(text, ":room")
                .ok_or_else(|| MlsError::Rejected("idkey missing :room".into()))?;
            let nonce = kw_u64(text, ":nonce").unwrap_or(0);
            let sig = kw_b64(text, ":sig")
                .ok_or_else(|| MlsError::Rejected("idkey missing :sig".into()))?;
            self.pins
                .apply_idkey(&handle, &key, &room, nonce, &sig, &self.room)
                .map(|_| ())
        })();
        match result {
            Ok(()) => SessionEvent::Handled { outbound: vec![] },
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
        let evidence: Option<RemovalEvidence> = kw_b64(text, ":evidence")
            .and_then(|bytes| serde_json::from_slice(&bytes).ok());
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
            let outcome = add_member(
                &self.provider,
                &self.identity,
                group,
                &kp,
                &target,
                &self.pins,
                &self.ledger,
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

    /// Presence may PROMPT an add decision (never a removal — REQ-014): when
    /// we are the elected owner, fetch KeyPackages for present non-members.
    fn on_presence(&mut self, text: &str) -> SessionEvent {
        let Some(group) = self.group.as_ref() else {
            return SessionEvent::Handled { outbound: vec![] };
        };
        let am_owner = is_owner(group, &self.identity).unwrap_or_default();
        if !am_owner {
            return SessionEvent::Handled { outbound: vec![] };
        }
        let members: std::collections::HashSet<String> = group
            .members()
            .filter_map(|m| super::group::credential_handle(&m.credential).ok())
            .collect();
        let outbound = presence_handles(text)
            .into_iter()
            .filter(|h| !members.contains(h) && h != &self.handle)
            .map(|h| format!("(keyget @hub :for {h} :from {})", self.handle))
            .collect();
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
    pub fn remove_with_evidence(
        &mut self,
        evidence: &RemovalEvidence,
    ) -> Result<String, MlsError> {
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

/// The first @-symbol after the performative (e.g. the asserted handle of
/// an idkey, the room of a deliver).
fn head_target(text: &str) -> Option<String> {
    parse_list(text)?.iter().skip(1).find_map(|item| match item {
        SExpr::Atom(Atom::Symbol(s)) if s.starts_with('@') => Some(s.clone()),
        _ => None,
    })
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

        let err = session.on_roomcfg("(roomcfg @research :enc false)").unwrap_err();
        assert!(matches!(err, MlsError::Rejected(_)));
        assert!(session.downgrade_refused());

        // Fail closed: no sends, ever, in this state.
        let err = session.encrypt_outbound("(say @research :from @aria :text \"x\")");
        assert!(err.is_err(), "must refuse to send after a downgrade attempt");
        let _ = fs::remove_dir_all(&dir);
    }

    /// REQ-023: an unpinned private join cannot send plaintext either — an
    /// un-joined encrypted session refuses to emit content.
    #[test]
    fn no_plaintext_before_join() {
        let (dir, wire) = setup("nojoin", 82, "@aria");
        let mut session =
            MlsSession::open(&dir, "aria", "@research", "@aria", &wire, true).unwrap();
        assert!(session.encrypt_outbound("(say @research :from @aria)").is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    /// The pin persists across restarts even when no cap is re-presented.
    #[test]
    fn mode_pin_persists() {
        let (dir, wire) = setup("pinpersist", 83, "@aria");
        {
            let _ = MlsSession::open(&dir, "aria", "@research", "@aria", &wire, true).unwrap();
        }
        let session =
            MlsSession::open(&dir, "aria", "@research", "@aria", &wire, false).unwrap();
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
        assert_eq!(frames.len(), 2);
        assert!(frames[0].starts_with("(keypub @hub :last \""));
        assert!(frames[0].contains(":onetime ("));
        assert!(cbcl_parser::parse(&frames[0]).is_ok(), "keypub parses");

        // The idkey frame round-trips through a peer's pin store.
        assert!(frames[1].starts_with("(idkey @aria"));
        let (peer_dir, _) = setup("joinframes-peer", 85, "@peer");
        let mut peer = PinStore::open(&peer_dir.join("peer.pins")).unwrap();
        let handle = head_target(&frames[1]).unwrap();
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
    #[test]
    fn full_session_flow_over_frames() {
        let (a_dir, a_wire) = setup("flow", 86, "@alice");
        let (b_dir, b_wire) = setup("flow", 87, "@bob");

        let mut alice =
            MlsSession::open(&a_dir, "alice", "@research", "@alice", &a_wire, true).unwrap();
        let mut bob =
            MlsSession::open(&b_dir, "bob", "@research", "@bob", &b_wire, true).unwrap();

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

        // Presence prompts the owner to fetch bob's KeyPackage.
        let SessionEvent::Handled { outbound } =
            alice.handle_frame("(presence @research :members (@alice @bob))")
        else {
            panic!("presence handled")
        };
        assert_eq!(outbound, vec!["(keyget @hub :for @bob :from @alice)".to_string()]);

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
}
