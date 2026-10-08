//! Group lifecycle (REQ-001, REQ-003, REQ-004, REQ-008, REQ-012, REQ-016).
//!
//! - **Creation** writes the creator-signed genesis assertion into the
//!   GroupContext as an application extension and asserts the genesis
//!   capability in the create config (K-2: fail at creation, not at the
//!   first path-commit where openmls would otherwise brick the group).
//! - **Election** is deterministic over the MLS ratchet-tree leaves —
//!   authenticated, consistent state — never hub presence (REQ-004/REQ-016).
//! - **Adding** verifies the fetched KeyPackage's credential identity is the
//!   intended target AND its leaf key equals that handle's pinned wire key
//!   (REQ-008); hub-asserted keys are never trusted.
//! - **Joining** validates the Welcome app-bound and full-tree pin-checked
//!   (REQ-012): room binding via the genesis, authorised committer, no
//!   silent group replacement, and every leaf checked against pins — with
//!   the REQ-013 rollback guarantee that a rejected Welcome leaves the
//!   one-time init key intact.

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use openmls::group::GroupId;
use openmls::prelude::{
    BasicCredential, Credential, Extension, Extensions, KeyPackage, MlsGroup, MlsGroupCreateConfig,
    MlsGroupJoinConfig, MlsMessageBodyIn, MlsMessageIn, SenderRatchetConfiguration, StagedWelcome,
    UnknownExtension,
};
use openmls_traits::OpenMlsProvider as _;
use tls_codec::{DeserializeBytes as _, Serialize as _};

use super::keypackages::{ConsumedLedger, validate_key_package_bytes, welcome_refs};
use super::pins::{PinStore, lp};
use super::provider::DurableProvider;
use super::{
    CIPHERSUITE, DS_MLS_GENESIS, GENESIS_EXT_TYPE, MlsError, MlsIdentity, genesis_capabilities,
};
use crate::chat_frame::FrameSigner;

/// NFR-004 retention knobs, applied to every group this module creates or
/// joins: no past-epoch secrets, no resumption PSKs, a bounded in-epoch
/// out-of-order window.
const MAX_PAST_EPOCHS: usize = 0;
const RESUMPTION_PSKS: usize = 0;
const OUT_OF_ORDER_TOLERANCE: u32 = 5;
const MAX_FORWARD_DISTANCE: u32 = 1000;

fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .max_past_epochs(MAX_PAST_EPOCHS)
        .number_of_resumption_psks(RESUMPTION_PSKS)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(
            OUT_OF_ORDER_TOLERANCE,
            MAX_FORWARD_DISTANCE,
        ))
        .build()
}

/// The creator-signed group-genesis assertion (REQ-016): `(genesis @room
/// :creator @h :group <group-id> :key K)` signed by K under its own DS
/// label. Authoritative only when K is already pinned or independently
/// authenticated; otherwise documented first-group-wins TOFU + mandatory
/// safety-number confirmation.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct GenesisAssertion {
    pub room: String,
    pub creator_handle: String,
    pub group_id_b64: String,
    pub creator_key_b64: String,
    pub signature_b64: String,
}

/// How much authority the verified genesis carries (REQ-016, R4-03).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum GenesisTrust {
    /// The creator key was already pinned (or out-of-band anchored) and
    /// matches: the assertion is authoritative.
    Authoritative,
    /// First contact: the creator key was first observed from the assertion
    /// itself — self-signed TOFU. The join requires REQ-021 safety-number
    /// confirmation before the group is treated as authentic.
    TofuRequiresSafetyNumber,
}

/// The `cbcl-mls-genesis/v1` signed context.
pub fn genesis_signing_bytes(
    room: &str,
    creator_handle: &str,
    group_id: &[u8],
    creator_key: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::new();
    lp(&mut out, DS_MLS_GENESIS.as_bytes());
    lp(&mut out, room.as_bytes());
    lp(&mut out, creator_handle.as_bytes());
    lp(&mut out, group_id);
    lp(&mut out, creator_key);
    out
}

/// SPEC-061 CON-002: the creator-signed admission grant, as it travels. Serde
/// field names are wire-visible and MUST match cbcl-bus's `AdmissionGrant`
/// (crates/cbcl-mls-wasm) — SPEC-061 OQ-001.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AdmissionGrant {
    pub room: String,
    pub creator_handle: String,
    pub token_digest_b64: String,
    pub not_after_ms: u64,
    pub sig_b64: String,
}

/// What a joiner puts in an external Commit's AAD (SPEC-061 CON-001): the invite
/// token being redeemed, and the creator's grant over that token's digest. In the
/// AAD rather than beside the frame so the joiner's own signature over the
/// FramedContent covers it — a relay cannot re-pair a valid grant with a commit
/// the creator never authorised. MUST match cbcl-bus's `ExternalAdmission`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExternalAdmission {
    pub token_b64: String,
    pub grant_json: String,
}

/// SPEC-061 CON-006: the PAIRING admission grant, as it travels. Serde field
/// names are wire-visible and MUST match cbcl-bus's `PairingGrant`.
///
/// A CLOSED record (`deny_unknown_fields`): exactly `kind`, `room`,
/// `group_id_b64`, `signer_handle`, `signer_key_b64`, `subject_handle`,
/// `subject_key_b64`, `not_after_ms`, `sig_b64`, every one required. A v1 record
/// (no `group_id_b64`) does not parse as v2, and its `kind` is refused before any
/// parse is attempted (see [`verify_admission_authority`]).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingGrant {
    /// The discriminator, and it is REQUIRED. A grant JSON without it is a CON-002
    /// [`AdmissionGrant`] and is checked by those rules; the two never fall through
    /// to each other, because a credential checked under whichever rules happen to
    /// parse is a credential with the weaker of the two.
    pub kind: String,
    pub room: String,
    /// Base64 (standard) of the raw MLS group identifier of the signer's admitted
    /// group (pairing v2). Verified equal to the group being judged.
    pub group_id_b64: String,
    pub signer_handle: String,
    pub signer_key_b64: String,
    pub subject_handle: String,
    pub subject_key_b64: String,
    pub not_after_ms: u64,
    pub sig_b64: String,
}

impl PairingGrant {
    /// Mint a grant authorising `(subject_handle, subject_key)` to seat itself in
    /// `group`, the signer's own ADMITTED group for `room`.
    ///
    /// The group identifier is read from `group` and from nowhere else: a group id
    /// supplied by the hub (or any caller-chosen bytes) is not minting authority,
    /// because the signer would then be vouching for a group it has never seen.
    /// [`super::session::MlsSession::sign_pairing_grant`] is the session entry
    /// point and passes only the group it has installed.
    #[allow(clippy::too_many_arguments)]
    pub fn mint<S: FrameSigner>(
        signer: &S,
        signer_handle: &str,
        signer_key: &[u8; 32],
        group: &MlsGroup,
        room: &str,
        subject_handle: &str,
        subject_key: &[u8; 32],
        not_after_ms: u64,
    ) -> Self {
        Self::mint_for_group_id(
            signer,
            signer_handle,
            signer_key,
            group.group_id().as_slice(),
            room,
            subject_handle,
            subject_key,
            not_after_ms,
        )
    }

    /// The signing step itself, over explicit group bytes. Private so production
    /// can only reach it through [`PairingGrant::mint`]; tests use it to build
    /// wrong-group and known-answer grants.
    #[allow(clippy::too_many_arguments)]
    fn mint_for_group_id<S: FrameSigner>(
        signer: &S,
        signer_handle: &str,
        signer_key: &[u8; 32],
        group_id: &[u8],
        room: &str,
        subject_handle: &str,
        subject_key: &[u8; 32],
        not_after_ms: u64,
    ) -> Self {
        let signed = super::pins::pairgrant_signing_bytes(
            room,
            group_id,
            signer_handle,
            signer_key,
            subject_handle,
            subject_key,
            not_after_ms,
        );
        Self {
            kind: super::DS_MLS_PAIRGRANT.to_string(),
            room: room.to_string(),
            group_id_b64: B64.encode(group_id),
            signer_handle: signer_handle.to_string(),
            signer_key_b64: B64.encode(signer_key),
            subject_handle: subject_handle.to_string(),
            subject_key_b64: B64.encode(subject_key),
            not_after_ms,
            sig_b64: B64.encode(signer.sign(&signed)),
        }
    }

    /// Verify against the group being judged, and against the leaf the joiner
    /// presents (SPEC-061 REQ-008 / CON-006). Every input that decides anything
    /// comes from one of those two — never from the grant, never from the hub —
    /// or the check is circular.
    ///
    /// `group_id` is that group's MLS identifier; `live_leaves` is the
    /// `(handle, key)` of every live leaf the joiner is not — the member's own
    /// tree before merge, or the joiner's GroupInfo tree minus its own new leaf —
    /// so both sides judge the same roster.
    ///
    /// Byte-for-byte the same policy as cbcl-bus's `PairingGrant::verify`, in the
    /// same order, so a grant one stack admits is one the other admits.
    pub fn verify(
        &self,
        group_id: &[u8],
        live_leaves: &[(String, Vec<u8>)],
        room: &str,
        joiner_handle: &str,
        joiner_key: &[u8],
        now_ms: u64,
    ) -> Result<(), MlsError> {
        if self.kind != super::DS_MLS_PAIRGRANT {
            return Err(MlsError::Rejected(format!(
                "pairing grant has kind {}, not {} (SPEC-061 CON-006)",
                self.kind,
                super::DS_MLS_PAIRGRANT
            )));
        }
        if self.room != room {
            return Err(MlsError::Rejected(format!(
                "pairing grant is bound to {}, not {room} (SPEC-061 REQ-008)",
                self.room
            )));
        }
        // (1) The group (v2). A grant for one group is unusable in any other —
        // including a rival group under the same room name that carries a copy of
        // the signer's public leaf, which satisfies every check below.
        let bound_group = B64
            .decode(&self.group_id_b64)
            .map_err(|_| MlsError::Rejected("pairing grant group id is malformed".into()))?;
        if bound_group != group_id {
            return Err(MlsError::Rejected(
                "pairing grant is bound to a different MLS group than the one being joined \
                 (SPEC-061 REQ-008, group-bound pairing v2)"
                    .into(),
            ));
        }
        if self.not_after_ms <= now_ms {
            return Err(MlsError::Rejected(
                "pairing grant has expired (SPEC-061 REQ-008)".into(),
            ));
        }

        // (2) The signer is a LIVE LEAF PAIR of THIS tree. Not a pin (a belief
        // about a handle), not the genesis (which names one member), and nothing
        // the hub said: the ratchet tree being changed.
        //
        // Exactly one leaf, because a handle on two leaves is a tree we do not
        // understand, and picking either would be choosing whose authority to
        // honour by iteration order.
        let signer_key: [u8; 32] = B64
            .decode(&self.signer_key_b64)
            .ok()
            .and_then(|k| <[u8; 32]>::try_from(k).ok())
            .ok_or_else(|| MlsError::Rejected("pairing grant signer key is malformed".into()))?;
        let mut seats = live_leaves
            .iter()
            .filter(|(handle, _)| *handle == self.signer_handle);
        match (seats.next(), seats.next()) {
            (Some((_, key)), None) => {
                if key.as_slice() != signer_key {
                    return Err(MlsError::Rejected(format!(
                        "pairing grant refused: {} is a live leaf, but not with the key the grant \
                         signs under (SPEC-061 REQ-008)",
                        self.signer_handle
                    )));
                }
            }
            (None, _) => {
                return Err(MlsError::Rejected(format!(
                    "pairing grant refused: {} is not a live leaf of this group, so it cannot \
                     authorise an admission to it (SPEC-061 REQ-008 / NFR-001)",
                    self.signer_handle
                )));
            }
            (Some(_), Some(_)) => {
                return Err(MlsError::Rejected(format!(
                    "pairing grant refused: {} names more than one live leaf; refusing to choose",
                    self.signer_handle
                )));
            }
        }

        // (4) The subject is exactly the leaf being seated. This is what lets the
        // grant travel in the clear: it authorises a KEY, so a party that reads it
        // and is not that key gains nothing it can use.
        if self.subject_handle != joiner_handle {
            return Err(MlsError::Rejected(format!(
                "pairing grant authorises {}, but the joining leaf is {joiner_handle} \
                 (SPEC-061 REQ-008)",
                self.subject_handle
            )));
        }
        let subject_key: [u8; 32] = B64
            .decode(&self.subject_key_b64)
            .ok()
            .and_then(|k| <[u8; 32]>::try_from(k).ok())
            .ok_or_else(|| MlsError::Rejected("pairing grant subject key is malformed".into()))?;
        if subject_key.as_slice() != joiner_key {
            return Err(MlsError::Rejected(format!(
                "pairing grant authorises a different key for {joiner_handle} than the one its \
                 leaf presents (SPEC-061 REQ-008 — the grant is bound to a key, not a name)"
            )));
        }

        // (3) …and the signature covers all of it, the group included.
        let sig = B64
            .decode(&self.sig_b64)
            .map_err(|e| MlsError::Rejected(format!("pairing grant signature: {e}")))?;
        let signed = super::pins::pairgrant_signing_bytes(
            room,
            group_id,
            &self.signer_handle,
            &signer_key,
            &self.subject_handle,
            &subject_key,
            self.not_after_ms,
        );
        let vk = VerifyingKey::from_bytes(&signer_key)
            .map_err(|_| MlsError::Rejected("pairing grant signer key is not a valid Ed25519 key".into()))?;
        let sig = Signature::from_slice(&sig)
            .map_err(|_| MlsError::Rejected("pairing grant signature is malformed".into()))?;
        vk.verify(&signed, &sig).map_err(|_| {
            MlsError::Rejected(
                "pairing grant does not verify under the signing member's leaf key \
                 (SPEC-061 REQ-008 / NFR-001)"
                    .into(),
            )
        })
    }
}

/// SPEC-061 REQ-002 / REQ-008: does `grant_json` authorise `(joiner_handle,
/// joiner_key)` into the group `group_id` of `room`? The one decision both sides
/// make — a member before merging an external Commit, and the joiner before
/// installing the group it would commit into — so the two cannot disagree about
/// what a grant authorises. Mirrors cbcl-bus's `verify_admission_authority`.
///
/// Dispatch is on the PRESENCE of `kind`, not on its value. Absent: a CON-002
/// invite grant, authorised by the genesis creator over `token`. Present: it MUST
/// be exactly the current pairing kind — the retired `cbcl-mls-pairgrant/v1`, any other
/// version, or a non-string is refused here and never re-tried as an invite. A
/// credential checked under whichever rules happen to parse is a credential with
/// the weaker of the two.
#[allow(clippy::too_many_arguments)]
pub fn verify_admission_authority(
    grant_json: &str,
    token_b64: &str,
    room: &str,
    group_id: &[u8],
    joiner_handle: &str,
    joiner_key: &[u8],
    live_leaves: &[(String, Vec<u8>)],
    genesis: &GenesisAssertion,
    now_ms: u64,
) -> Result<(), MlsError> {
    let value = serde_json::from_str::<serde_json::Value>(grant_json)
        .map_err(|e| MlsError::Rejected(format!("admission grant json: {e}")))?;
    match value.get("kind") {
        Some(serde_json::Value::String(kind)) if kind == super::DS_MLS_PAIRGRANT => {
            // SPEC-061 REQ-008: authorised by a member of THIS group, bound to this
            // exact leaf. No genesis is consulted for authority — the authority is
            // the tree being judged.
            let grant: PairingGrant = serde_json::from_value(value)
                .map_err(|e| MlsError::Rejected(format!("pairing grant json: {e}")))?;
            grant.verify(group_id, live_leaves, room, joiner_handle, joiner_key, now_ms)
        }
        Some(other) => Err(MlsError::Rejected(format!(
            "admission grant kind {other} is not supported; only {} pairing grants are \
             accepted, and an unsupported pairing kind is never re-read as an invite \
             (SPEC-061 CON-006, group-bound pairing v2)",
            super::DS_MLS_PAIRGRANT
        ))),
        None => {
            // SPEC-061 REQ-002: authorised by the creator, bearer, bound to a token.
            let creator_key = genesis.creator_key()?;
            let token = B64
                .decode(token_b64)
                .map_err(|e| MlsError::Rejected(format!("admission token: {e}")))?;
            let grant: AdmissionGrant = serde_json::from_value(value)
                .map_err(|e| MlsError::Rejected(format!("admission grant json: {e}")))?;
            grant.verify(room, &genesis.creator_handle, &creator_key, &token, now_ms)
        }
    }
}

/// `(handle, key)` of every live leaf with a basic credential, excluding leaf
/// `skip` (the joiner's own new leaf, on the joiner side). A non-basic leaf can
/// authorise nothing, so it is left out rather than failing the whole roster —
/// the same tolerance the v1 member-side lookup had.
pub(crate) fn live_leaf_bindings(group: &MlsGroup, skip: Option<u32>) -> Vec<(String, Vec<u8>)> {
    group
        .members()
        .filter(|m| Some(m.index.u32()) != skip)
        .filter_map(|m| credential_handle(&m.credential).ok().map(|h| (h, m.signature_key)))
        .collect()
}

impl AdmissionGrant {
    /// Mint a grant for `room` over `token`, valid until `not_after_ms`.
    ///
    /// Only meaningful on the channel's CREATOR (SPEC-061 REQ-003) — members
    /// verify against the key the group's genesis names, so a grant signed by
    /// anybody else is refused by every member. A misuse is inert, not dangerous,
    /// but it is still a misuse.
    pub fn mint<S: FrameSigner>(
        signer: &S,
        creator_handle: &str,
        creator_key: &[u8; 32],
        room: &str,
        token: &[u8],
        not_after_ms: u64,
    ) -> Self {
        use sha2::{Digest as _, Sha256};
        let digest = Sha256::digest(token);
        let signed = super::pins::invite_signing_bytes(room, creator_key, &digest, not_after_ms);
        Self {
            room: room.to_string(),
            creator_handle: creator_handle.to_string(),
            token_digest_b64: B64.encode(digest),
            not_after_ms,
            sig_b64: B64.encode(signer.sign(&signed)),
        }
    }

    /// Verify this grant against the room and creator the GROUP itself asserts
    /// (SPEC-061 REQ-002). `creator_handle`/`creator_key` MUST come from the
    /// group's own genesis assertion — never from this grant and never from the
    /// wire, or the check is circular and an untrusted hub could mint admissions
    /// at will.
    pub fn verify(
        &self,
        room: &str,
        creator_handle: &str,
        creator_key: &[u8; 32],
        token: &[u8],
        now_ms: u64,
    ) -> Result<(), MlsError> {
        use sha2::{Digest as _, Sha256};
        if self.room != room {
            return Err(MlsError::Rejected(format!(
                "admission grant is bound to {}, not {room} (SPEC-061 REQ-002)",
                self.room
            )));
        }
        if self.creator_handle != creator_handle {
            return Err(MlsError::Rejected(format!(
                "admission grant names {} as creator, but this group's genesis names {creator_handle}",
                self.creator_handle
            )));
        }
        if self.not_after_ms <= now_ms {
            return Err(MlsError::Rejected(
                "admission grant has expired (SPEC-061 REQ-002)".into(),
            ));
        }
        let digest = Sha256::digest(token);
        let asserted = B64
            .decode(&self.token_digest_b64)
            .map_err(|e| MlsError::Rejected(format!("grant token digest: {e}")))?;
        if asserted.as_slice() != digest.as_slice() {
            return Err(MlsError::Rejected(
                "admission grant is not for the token presented (SPEC-061 REQ-002)".into(),
            ));
        }
        let sig = B64
            .decode(&self.sig_b64)
            .map_err(|e| MlsError::Rejected(format!("grant signature: {e}")))?;
        let signed = super::pins::invite_signing_bytes(room, creator_key, &digest, self.not_after_ms);
        let vk = VerifyingKey::from_bytes(creator_key)
            .map_err(|_| MlsError::Rejected("genesis creator key is not a valid Ed25519 key".into()))?;
        let sig = Signature::from_slice(&sig)
            .map_err(|_| MlsError::Rejected("admission grant signature is malformed".into()))?;
        vk.verify(&signed, &sig).map_err(|_| {
            MlsError::Rejected(
                "admission grant does not verify under this channel's genesis creator key \
                 (SPEC-061 REQ-002 / NFR-001)"
                    .into(),
            )
        })
    }
}

impl GenesisAssertion {
    pub fn mint<S: FrameSigner>(
        signer: &S,
        creator_handle: &str,
        creator_key: &[u8; 32],
        room: &str,
        group_id: &[u8],
    ) -> Self {
        let signed = genesis_signing_bytes(room, creator_handle, group_id, creator_key);
        Self {
            room: room.to_string(),
            creator_handle: creator_handle.to_string(),
            group_id_b64: B64.encode(group_id),
            creator_key_b64: B64.encode(creator_key),
            signature_b64: B64.encode(signer.sign(&signed)),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("genesis serializes")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MlsError> {
        serde_json::from_slice(bytes)
            .map_err(|e| MlsError::Rejected(format!("genesis assertion malformed: {e}")))
    }

    /// The creator key bytes.
    pub fn creator_key(&self) -> Result<[u8; 32], MlsError> {
        let bytes = B64
            .decode(&self.creator_key_b64)
            .map_err(|e| MlsError::Rejected(format!("genesis creator key: {e}")))?;
        <[u8; 32]>::try_from(bytes.as_slice())
            .map_err(|_| MlsError::Rejected("genesis creator key is not 32 bytes".into()))
    }

    /// Verify the self-signature and the (room, group) binding, then grade
    /// its authority against the pin store (REQ-016): a pinned creator key
    /// that MATCHES → authoritative; a pinned key that CONFLICTS → hard
    /// reject (the hub presented a rival creator); unpinned → TOFU, the
    /// caller must require safety-number confirmation.
    pub fn verify(
        &self,
        expected_room: &str,
        expected_group_id: &[u8],
        pins: &PinStore,
    ) -> Result<GenesisTrust, MlsError> {
        if self.room != expected_room {
            return Err(MlsError::Rejected(format!(
                "genesis bound to room {}, not {expected_room}",
                self.room
            )));
        }
        let group_id = B64
            .decode(&self.group_id_b64)
            .map_err(|e| MlsError::Rejected(format!("genesis group id: {e}")))?;
        if group_id != expected_group_id {
            return Err(MlsError::Rejected(
                "genesis bound to a different group id".into(),
            ));
        }
        let key = self.creator_key()?;
        let signed = genesis_signing_bytes(&self.room, &self.creator_handle, &group_id, &key);
        let signature = B64
            .decode(&self.signature_b64)
            .map_err(|e| MlsError::Rejected(format!("genesis signature: {e}")))?;
        let vk = VerifyingKey::from_bytes(&key)
            .map_err(|_| MlsError::Rejected("genesis creator key invalid".into()))?;
        let sig = Signature::from_slice(&signature)
            .map_err(|_| MlsError::Rejected("genesis signature malformed".into()))?;
        vk.verify(&signed, &sig)
            .map_err(|_| MlsError::Rejected("genesis self-signature invalid".into()))?;

        match pins.pinned(&self.creator_handle) {
            Some(pin) if pin.key == key => Ok(GenesisTrust::Authoritative),
            Some(_) => Err(MlsError::Rejected(format!(
                "genesis creator key for {} conflicts with the pinned wire key",
                self.creator_handle
            ))),
            None => Ok(GenesisTrust::TofuRequiresSafetyNumber),
        }
    }
}

/// Deterministic owner election over (handle, leaf-signature-key) pairs from
/// the MLS leaves (REQ-004, REQ-016): lexicographically smallest handle
/// bytes win, leaf key as tie-breaker. Every correct client computes the
/// same committer for the same tree.
pub fn elect_owner(members: &[(String, Vec<u8>)]) -> Option<(String, Vec<u8>)> {
    members
        .iter()
        .min_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()).then(a.1.cmp(&b.1)))
        .cloned()
}

/// Creator-preferred committer election (REQ-004/012b/016): the GENESIS CREATOR
/// when it is a live leaf (matched on BOTH handle and key — duplicate-handle
/// safety), else the lexicographically-smallest leaf (via [`elect_owner`]) for a
/// creatorless / genesis-less group.
///
/// Preferring the creator makes it the single, stable committer and stops a
/// passive AGENT leaf that merely sorts first from being elected committer —
/// agents never commit, which would otherwise deadlock every FURTHER membership
/// change once such an agent is admitted.
///
/// MUST stay byte-for-byte equivalent to cbcl-mls-wasm's `elect_committer`
/// (the web stack), or a web-committed Add/Welcome is rejected by hark (and vice
/// versa) — the cross-stack owner-election invariant.
pub fn elect_committer(
    members: &[(String, Vec<u8>)],
    creator: Option<&(String, Vec<u8>)>,
) -> Option<(String, Vec<u8>)> {
    if let Some(c) = creator {
        if members.iter().any(|m| m == c) {
            return Some(c.clone());
        }
    }
    elect_owner(members)
}

/// The genesis creator `(handle, wire key)` for a live group, when it carries a
/// verifiable genesis extension (REQ-016). `None` for a genesis-less group, which
/// then falls back to lex-smallest election.
pub fn group_genesis_creator(group: &MlsGroup) -> Option<(String, Vec<u8>)> {
    let bytes = group.extensions().unknown(GENESIS_EXT_TYPE)?.0.clone();
    let g = GenesisAssertion::from_bytes(&bytes).ok()?;
    let key = g.creator_key().ok()?;
    Some((g.creator_handle, key.to_vec()))
}

/// Extract `(handle, signature_key)` pairs from a group's live leaves.
pub fn member_bindings(group: &MlsGroup) -> Result<Vec<(String, Vec<u8>)>, MlsError> {
    group
        .members()
        .map(|m| {
            let handle = credential_handle(&m.credential)?;
            Ok((handle, m.signature_key))
        })
        .collect()
}

/// Decode a leaf credential into the canonical handle string.
pub fn credential_handle(credential: &Credential) -> Result<String, MlsError> {
    let basic = BasicCredential::try_from(credential.clone())
        .map_err(|e| MlsError::Rejected(format!("non-basic credential: {e:?}")))?;
    String::from_utf8(basic.identity().to_vec())
        .map_err(|_| MlsError::Rejected("credential identity is not utf-8".into()))
}

/// Is `identity` the elected owner of `group`'s current tree?
pub fn is_owner(group: &MlsGroup, identity: &MlsIdentity) -> Result<bool, MlsError> {
    let members = member_bindings(group)?;
    Ok(elect_committer(&members, group_genesis_creator(group).as_ref())
        .map(|(handle, key)| handle == identity.handle && key == identity.public_key())
        .unwrap_or(false))
}

/// Create the room's group: random group id, genesis assertion in the
/// GroupContext, genesis capability asserted in the create config (K-2).
pub fn create_group(
    provider: &DurableProvider,
    identity: &MlsIdentity,
    room: &str,
) -> Result<(MlsGroup, GenesisAssertion), MlsError> {
    let group_id_bytes: [u8; 32] = rand::random();
    let creator_key = <[u8; 32]>::try_from(identity.public_key())
        .map_err(|_| MlsError::Rejected("identity key is not 32 bytes".into()))?;
    let genesis = GenesisAssertion {
        room: room.to_string(),
        creator_handle: identity.handle.clone(),
        group_id_b64: B64.encode(group_id_bytes),
        creator_key_b64: B64.encode(creator_key),
        signature_b64: String::new(),
    };
    // Sign via the MLS signer (the same wire key, REQ-007).
    let signed = genesis_signing_bytes(room, &identity.handle, &group_id_bytes, &creator_key);
    let signature = {
        use openmls_traits::signatures::Signer as _;
        identity
            .signer
            .sign(&signed)
            .map_err(MlsError::stack("sign genesis"))?
    };
    let genesis = GenesisAssertion {
        signature_b64: B64.encode(signature),
        ..genesis
    };

    let extensions = Extensions::single(Extension::Unknown(
        GENESIS_EXT_TYPE,
        UnknownExtension(genesis.to_bytes()),
    ))
    .map_err(MlsError::stack("genesis extension"))?;

    let config = MlsGroupCreateConfig::builder()
        .use_ratchet_tree_extension(true)
        .ciphersuite(CIPHERSUITE)
        .max_past_epochs(MAX_PAST_EPOCHS)
        .number_of_resumption_psks(RESUMPTION_PSKS)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(
            OUT_OF_ORDER_TOLERANCE,
            MAX_FORWARD_DISTANCE,
        ))
        .capabilities(genesis_capabilities())
        .with_group_context_extensions(extensions)
        .build();

    let group = MlsGroup::new_with_group_id(
        provider,
        &identity.signer,
        &config,
        GroupId::from_slice(&group_id_bytes),
        identity.credential.clone(),
    )
    .map_err(MlsError::stack("create group"))?;

    // K-2 creator-capability guard: openmls ACCEPTS a default-capability
    // creator with a genesis extension and bricks the group at its first
    // path-commit instead (§10 method note); assert the created leaf
    // advertises the genesis extension type, failing here — before the
    // first real Commit — and never persisting the doomed group.
    assert_creator_capability(&group)?;
    provider.persist()?;
    Ok((group, genesis))
}

/// K-2: the creator's own leaf must advertise the genesis extension type.
fn assert_creator_capability(group: &MlsGroup) -> Result<(), MlsError> {
    use openmls::prelude::ExtensionType;
    let advertised = group
        .own_leaf_node()
        .map(|leaf| {
            leaf.capabilities()
                .extensions()
                .contains(&ExtensionType::Unknown(GENESIS_EXT_TYPE))
        })
        .unwrap_or(false);
    if !advertised {
        return Err(MlsError::Rejected(format!(
            "K-2 guard: creator leaf does not advertise genesis extension type \
             {GENESIS_EXT_TYPE:#06x}; the group would brick at its first path-commit"
        )));
    }
    Ok(())
}

/// REQ-008 adder verification: the fetched KeyPackage's credential identity
/// must be the intended target handle AND its leaf signature key must equal
/// that handle's pinned wire key — never a hub-asserted key.
pub fn verify_add_target(
    kp: &KeyPackage,
    target_handle: &str,
    pins: &PinStore,
) -> Result<(), MlsError> {
    let handle = credential_handle(kp.leaf_node().credential())?;
    if handle != target_handle {
        return Err(MlsError::Rejected(format!(
            "key package credential is {handle}, not the intended target {target_handle}"
        )));
    }
    let pin = pins.pinned(target_handle).ok_or_else(|| {
        MlsError::Rejected(format!(
            "no pinned wire key for {target_handle}; refusing to add from a hub-asserted key \
             (REQ-008/REQ-011: pin from the target's own signed frames first)"
        ))
    })?;
    if kp.leaf_node().signature_key().as_slice() != pin.key {
        return Err(MlsError::Rejected(format!(
            "key package leaf key for {target_handle} does not equal the pinned wire key"
        )));
    }
    Ok(())
}

/// The result of committing an Add: both objects TLS-serialized for the wire.
pub struct AddOutcome {
    pub commit_bytes: Vec<u8>,
    pub welcome_bytes: Vec<u8>,
    /// One-time KeyPackage ref to consume after canonical admission.
    pub consumed_ref: Option<String>,
}

/// REQ-003: add `target_handle` using their fetched KeyPackage, with full
/// REQ-008 verification, single-use ref checking (REQ-013), and owner-only
/// committing (REQ-016). Merges own commit and persists.
#[allow(clippy::too_many_arguments)]
pub fn add_member(
    provider: &DurableProvider,
    identity: &MlsIdentity,
    group: &mut MlsGroup,
    kp_bytes: &[u8],
    target_handle: &str,
    pins: &PinStore,
    ledger: &mut ConsumedLedger,
    room: &str,
    promise: super::claim::CommitPromise<'_>,
) -> Result<AddOutcome, MlsError> {
    add_member_inner(provider, identity, group, kp_bytes, target_handle, pins, ledger, room, promise, true)
}

/// Build an Add while retaining OpenMLS's pending commit. `mls-ds/v1`
/// callers persist this state and submit the exact bytes to the DS; only the
/// admitted record may merge it.
#[allow(clippy::too_many_arguments)]
pub fn stage_add_member(
    provider: &DurableProvider,
    identity: &MlsIdentity,
    group: &mut MlsGroup,
    kp_bytes: &[u8],
    target_handle: &str,
    pins: &PinStore,
    ledger: &mut ConsumedLedger,
    room: &str,
) -> Result<AddOutcome, MlsError> {
    add_member_inner(
        provider,
        identity,
        group,
        kp_bytes,
        target_handle,
        pins,
        ledger,
        room,
        super::claim::CommitPromise::Inactive,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
fn add_member_inner(
    provider: &DurableProvider,
    identity: &MlsIdentity,
    group: &mut MlsGroup,
    kp_bytes: &[u8],
    target_handle: &str,
    pins: &PinStore,
    ledger: &mut ConsumedLedger,
    room: &str,
    promise: super::claim::CommitPromise<'_>,
    merge_now: bool,
) -> Result<AddOutcome, MlsError> {
    if !is_owner(group, identity)? {
        return Err(MlsError::Rejected(
            "not the elected owner for the current tree; refusing to commit an Add (REQ-016)"
                .into(),
        ));
    }
    // Refuse to add a handle that is already a member. The KeyPackage
    // directory is the untrusted hub; an unsolicited or replayed `keypkg` for
    // an existing member (with a fresh one-time ref the ledger hasn't seen)
    // would otherwise commit a second leaf for the same handle — corrupting
    // the deterministic election, double-counting the REQ-021 safety number
    // (a false fork vs. web peers), and seating a duplicate decryptor.
    if member_bindings(group)?
        .iter()
        .any(|(handle, _)| handle == target_handle)
    {
        return Err(MlsError::Rejected(format!(
            "{target_handle} is already a member; refusing a duplicate-leaf Add"
        )));
    }
    let kp = validate_key_package_bytes(provider, kp_bytes)?;
    verify_add_target(&kp, target_handle, pins)?;

    // REQ-013 transcript-visible refs: refuse to commit an Add that reuses a
    // ref this client has seen consumed.
    let hash_ref = kp
        .hash_ref(provider.crypto())
        .map_err(MlsError::stack("hash ref"))?;
    let ref_b64 = B64.encode(hash_ref.as_slice());
    // Captured before `kp` is moved into the Add.
    let is_last_resort = kp.last_resort();
    if ledger.is_consumed(&ref_b64) {
        return Err(MlsError::Rejected(format!(
            "key package ref {ref_b64} already consumed; refusing replayed Add (REQ-013)"
        )));
    }

    // SPEC-027 REQ-001: the promise, checked before anything is generated.
    //
    // RFC 9420 §14 forbids a Commit from modifying a client's state — *because*
    // the client cannot know whether its Commit will conflict. §3.2 names the
    // escape: a promise from an orchestration server that this Commit is next.
    // An `ArmedClaim` IS that promise, which is why it is a type and not a
    // boolean: this function cannot be reached without one, or without the
    // caller saying explicitly that the room has not activated the protocol.
    if merge_now {
        check_promise(&promise, room, group.epoch().as_u64())?;
    }

    let (commit, welcome, _group_info) = group
        .add_members(provider, &identity.signer, &[kp])
        .map_err(MlsError::stack("add members"))?;
    if merge_now {
        group
            .merge_pending_commit(provider)
            .map_err(MlsError::stack("merge own add commit"))?;
    }
    // REQ-013: record what this Add SPENT.
    //
    // Without it the ledger only ever held refs consumed on the JOIN path — our
    // own packages, as a joiner — so the check above compared a target's ref
    // against a set it could never appear in. The guard read as live and matched
    // nothing, and an adder had no memory of which of the directory's packages
    // it had already used.
    //
    // That is the lever a hub wants on the REQ-026 heal path: it answers the
    // `keyget`, so it can serve the same package twice. The second Welcome is
    // sealed to an init key the target consumed the first time and can no longer
    // open — so the eviction lands and the re-add produces a Welcome nobody can
    // read. Marking here is what finally makes both this guard and the heal's
    // pre-check mean something.
    // ONE-TIME packages only. A last-resort package is reusable by design —
    // `keypackages.rs` documents its bound as the short MLS lifetime, "enforced
    // by the primitive, not prose" — and the pool is republished only on
    // connect, so once it drains the directory serves the last-resort for every
    // subsequent Add. Marking that consumed would refuse every member addition
    // in the channel until somebody reconnected.
    //
    // This is only decidable here because the flag now travels on the package
    // (see `build_key_package`); before that it was local state the adder could
    // not see.
    if merge_now && !is_last_resort {
        ledger.mark_consumed(&ref_b64)?;
    }
    provider.persist()?;
    Ok(AddOutcome {
        commit_bytes: commit
            .tls_serialize_detached()
            .map_err(MlsError::stack("serialize commit"))?,
        welcome_bytes: welcome
            .tls_serialize_detached()
            .map_err(MlsError::stack("serialize welcome"))?,
        consumed_ref: (!is_last_resort).then_some(ref_b64),
    })
}

/// [[SPEC-027 REQ-001]]: refuse to generate a Commit without the promise.
///
/// The epoch is re-checked here rather than trusted from when the claim was
/// armed. The group can move underneath a committer between arming and
/// merging — another member's Commit landing, a reconnect replaying history —
/// and a promise for epoch N says nothing about a merge at N+1.
pub(super) fn check_promise(
    promise: &super::claim::CommitPromise<'_>,
    room: &str,
    epoch: u64,
) -> Result<(), MlsError> {
    use super::claim::CommitPromise;
    match promise {
        // The room has not activated the protocol: commit as before. §14 is
        // unsatisfied for such a room, which is the status quo rather than a
        // regression — and is why activation must be unanimous.
        CommitPromise::Inactive => Ok(()),
        CommitPromise::Armed(claim) if claim.covers(room, epoch) => Ok(()),
        CommitPromise::Armed(claim) => Err(MlsError::Rejected(format!(
            "refusing to commit in {room} at epoch {epoch}: the armed claim covers \
             epoch {} — the group moved after the claim was armed, so the promise \
             does not cover this merge (SPEC-027 REQ-001)",
            claim.epoch()
        ))),
    }
}

/// A group this agent seated ITSELF into, plus the commit every existing member
/// must be given before any of them can read from us.
pub struct ExternalJoin {
    pub group: MlsGroup,
    /// MUST be sent. Until it lands and is merged, the members are at the old
    /// epoch and we are alone at the new one.
    pub commit: Vec<u8>,
    pub genesis: GenesisAssertion,
    pub trust: GenesisTrust,
}

/// SPEC-061 REQ-008 / CON-001: seat ourselves in `room`'s group by EXTERNAL
/// COMMIT (RFC 9420 §12.4.3.2), redeeming a pairing grant signed by the member
/// that paired us.
///
/// **hark has never minted one of these before**, and the asymmetry was
/// deliberate: an agent is never the party redeeming an *invitation*, so it only
/// ever needed to validate what somebody else built. REQ-008 makes the agent the
/// party being authorised, which makes it the party that has to build.
///
/// A GroupInfo arrives from the hub, which RFC 9420 §3 treats as largely
/// untrusted, so possession of one proves nothing. Before returning, this
/// requires, over the signature-verified GroupInfo's group (SPEC-103 ADR-007,
/// the joiner-side half cbcl-bus's `join_by_grant_verified` also applies):
/// - a genesis assertion bound to `room` and to this group id, self-signed, whose
///   creator key does not conflict with a pin (REQ-016);
/// - every pinned leaf in the tree carrying its pinned key, our own new leaf
///   included (REQ-012d);
/// - the grant authorising US by the rule every member applies at merge
///   ([`verify_admission_authority`]): for a pairing grant, the exact group id of
///   this GroupInfo, a live signer leaf other than us with the signed key, our
///   exact handle and key, `room`, unexpired at `now_ms`, signature valid; for an
///   invite grant, the genesis creator's signature over `room` and the token,
///   unexpired.
///
/// Building writes the new group into `provider`'s memory. On ANY refusal the
/// provider is rolled back to disk, so a refused GroupInfo leaves nothing to be
/// resumed, persisted or encrypted to — and `pins` is never written here.
///
/// The grant travels in the commit's AAD, so our own signature over the
/// FramedContent covers it and a relay cannot pair a valid grant with a different
/// commit.
pub fn join_by_grant(
    provider: &DurableProvider,
    identity: &MlsIdentity,
    group_info_bytes: &[u8],
    room: &str,
    grant_json: &str,
    pins: &mut PinStore,
    now_ms: u64,
) -> Result<ExternalJoin, MlsError> {
    let joined = build_external_join(provider, identity, group_info_bytes, room, grant_json, pins)?;
    match verify_external_join(&joined.group, identity, room, grant_json, &joined.genesis, pins, now_ms) {
        Ok(()) => Ok(joined),
        Err(e) => {
            drop(joined);
            provider.rollback_to_disk()?;
            Err(e)
        }
    }
}

/// The joiner's tree-pin and admission-authority checks over the group it has
/// built but not installed (the genesis is checked while building).
fn verify_external_join(
    group: &MlsGroup,
    identity: &MlsIdentity,
    room: &str,
    grant_json: &str,
    genesis: &GenesisAssertion,
    pins: &PinStore,
    now_ms: u64,
) -> Result<(), MlsError> {
    // REQ-012(d) over the whole tree, our own new leaf included.
    for member in group.members() {
        let handle = credential_handle(&member.credential)?;
        if let Some(pin) = pins.pinned(&handle) {
            if member.signature_key != pin.key {
                return Err(MlsError::Rejected(format!(
                    "group info tree leaf for {handle} does not match the pinned wire key \
                     (REQ-012d hard reject)"
                )));
            }
        }
    }
    // The grant, judged over the roster the members will judge it over: the tree
    // as it stood before our leaf was added. The token half of our AAD is empty —
    // hark only redeems pairing grants (SPEC-061 ADR-004).
    let own = group.own_leaf_index().u32();
    let others = live_leaf_bindings(group, Some(own));
    verify_admission_authority(
        grant_json,
        "",
        room,
        group.group_id().as_slice(),
        &identity.handle,
        identity.public_key(),
        &others,
        genesis,
        now_ms,
    )
}

/// Build the external Commit and the group it would seat us in, checking only
/// the genesis (room/group binding, self-signature, creator pin). NOT the grant
/// and NOT the tree pins: production goes through [`join_by_grant`]. Kept
/// separate so recipient-side tests can build the hostile Commits a member must
/// refuse — a joiner that refuses them itself would otherwise leave the member's
/// checks untested.
pub(crate) fn build_external_join(
    provider: &DurableProvider,
    identity: &MlsIdentity,
    group_info_bytes: &[u8],
    room: &str,
    grant_json: &str,
    pins: &PinStore,
) -> Result<ExternalJoin, MlsError> {
    use openmls::prelude::LeafNodeParameters;

    let msg = MlsMessageIn::tls_deserialize_exact_bytes(group_info_bytes)
        .map_err(|e| MlsError::Rejected(format!("group info deserialize: {e:?}")))?;
    let verifiable = match msg.extract() {
        MlsMessageBodyIn::GroupInfo(gi) => gi,
        other => {
            return Err(MlsError::Rejected(format!(
                "expected a GroupInfo, got {other:?}"
            )));
        }
    };

    // The token half of the AAD is empty on this flavour. An invite grant is
    // bearer and must at least be pinned to one invitation; a pairing grant
    // authorises a KEY in one GROUP, which binds harder than any token could
    // (SPEC-061 ADR-004).
    let admission = ExternalAdmission {
        token_b64: String::new(),
        grant_json: grant_json.to_string(),
    };
    let aad = serde_json::to_vec(&admission)
        .map_err(|e| MlsError::Rejected(format!("serialize admission: {e}")))?;

    let (group, bundle) = MlsGroup::external_commit_builder()
        .with_aad(aad)
        .with_config(join_config())
        .build_group(provider, verifiable, identity.credential.clone())
        .map_err(|e| MlsError::Rejected(format!("external commit build_group: {e:?}")))?
        .leaf_node_parameters(
            LeafNodeParameters::builder()
                .with_capabilities(genesis_capabilities())
                .build(),
        )
        .load_psks(provider.storage())
        .map_err(|e| MlsError::Rejected(format!("external commit psks: {e:?}")))?
        .build(provider.rand(), provider.crypto(), &identity.signer, |_| true)
        .map_err(|e| MlsError::Rejected(format!("external commit build: {e:?}")))?
        .finalize(provider)
        .map_err(|e| MlsError::Rejected(format!("external commit finalize: {e:?}")))?;

    // REQ-016, on the group we have just adopted. A GroupInfo comes from the hub,
    // and a hub that served us one for another channel — or one with no genesis at
    // all — would have us encrypting into a group with no verified relationship to
    // the room we joined. Rolled back rather than kept: a group we refuse to trust
    // must not survive in the provider to be resumed later as if it were fine.
    //
    // Necessary, not sufficient: a rival group's self-signed genesis by an
    // unpinned creator grades TOFU and passes here. What refuses that rival is the
    // pairing grant's group binding, checked in `join_by_grant`.
    let group_id = group.group_id().as_slice().to_vec();
    let genesis_bytes = match group.extensions().unknown(GENESIS_EXT_TYPE) {
        Some(ext) => ext.0.clone(),
        None => {
            provider.rollback_to_disk()?;
            return Err(MlsError::Rejected(
                "the GroupInfo's group carries no genesis extension (REQ-016)".into(),
            ));
        }
    };
    let (genesis, trust) = match GenesisAssertion::from_bytes(&genesis_bytes)
        .and_then(|g| g.verify(room, &group_id, pins).map(|t| (g, t)))
    {
        Ok(pair) => pair,
        Err(e) => {
            provider.rollback_to_disk()?;
            return Err(e);
        }
    };

    let (commit, _welcome, _group_info) = bundle.into_contents();
    let commit = commit
        .tls_serialize_detached()
        .map_err(|e| MlsError::Rejected(format!("serialize external commit: {e:?}")))?;
    Ok(ExternalJoin {
        group,
        commit,
        genesis,
        trust,
    })
}

/// A validated, joined group plus the genesis trust grade.
pub struct JoinOutcome {
    pub group: MlsGroup,
    pub genesis: GenesisAssertion,
    pub trust: GenesisTrust,
    /// The tree contained handles with no pin yet (first contact) — REQ-012:
    /// pin TOFU and require safety-number confirmation.
    pub first_contact_handles: Vec<String>,
}

/// REQ-001 + REQ-012: join from a Welcome with app-bound, full-tree,
/// pin-checked validation. On ANY rejection the provider is rolled back to
/// its durable state, leaving the one-time init key intact (REQ-013); only
/// a successful join persists (which deletes the consumed key from disk).
pub fn join_from_welcome(
    provider: &DurableProvider,
    identity: &MlsIdentity,
    welcome_bytes: &[u8],
    room: &str,
    pins: &mut PinStore,
    ledger: &mut ConsumedLedger,
    existing_group: Option<&[u8]>,
) -> Result<JoinOutcome, MlsError> {
    // (c) No silent replacement of an existing group for this room.
    if existing_group.is_some() {
        return Err(MlsError::Rejected(
            "a group already exists for this room; refusing silent replacement (REQ-012c)".into(),
        ));
    }

    let msg = MlsMessageIn::tls_deserialize_exact_bytes(welcome_bytes)
        .map_err(|e| MlsError::Rejected(format!("welcome deserialize: {e:?}")))?;
    let welcome = match msg.extract() {
        MlsMessageBodyIn::Welcome(w) => w,
        other => {
            return Err(MlsError::Rejected(format!(
                "expected a Welcome, got {other:?}"
            )));
        }
    };

    // REQ-013: a replayed Welcome addressed to an already-consumed package
    // is inert — rejected before any key material is touched. Capture the refs
    // now (the `welcome` is moved into staging below) so the durable
    // consumed-ledger can be written on a *successful* join.
    let welcome_refs = welcome_refs(&welcome);
    for ref_b64 in &welcome_refs {
        if ledger.is_consumed(ref_b64) {
            return Err(MlsError::Rejected(format!(
                "welcome reuses consumed KeyPackageRef {ref_b64} (replay)"
            )));
        }
    }

    // Staging consumes the init key in MEMORY; every failure path from here
    // rolls back so the durable state (and a reloaded memory state) keeps it.
    let staged = match StagedWelcome::new_from_welcome(provider, &join_config(), welcome, None) {
        Ok(staged) => staged,
        Err(e) => {
            provider.rollback_to_disk()?;
            return Err(MlsError::Rejected(format!("welcome staging: {e:?}")));
        }
    };

    match validate_staged_welcome(&staged, room, pins, &identity.handle) {
        Ok(()) => {}
        Err(e) => {
            provider.rollback_to_disk()?;
            return Err(e);
        }
    }

    // Pre-finalize genesis read (REQ-016 inspection point).
    let group_id = staged.group_context().group_id().as_slice().to_vec();
    let genesis_bytes = match staged
        .group_context()
        .extensions()
        .unknown(GENESIS_EXT_TYPE)
    {
        Some(ext) => ext.0.clone(),
        None => {
            provider.rollback_to_disk()?;
            return Err(MlsError::Rejected(
                "welcome's group carries no genesis extension (REQ-016)".into(),
            ));
        }
    };
    let genesis = match GenesisAssertion::from_bytes(&genesis_bytes)
        .and_then(|g| g.verify(room, &group_id, pins).map(|t| (g, t)))
    {
        Ok((genesis, trust)) => (genesis, trust),
        Err(e) => {
            provider.rollback_to_disk()?;
            return Err(e);
        }
    };
    let (genesis, trust) = genesis;

    // Collect first-contact handles (pin TOFU after the join succeeds).
    let mut first_contact = Vec::new();
    let mut tofu_pins: Vec<(String, [u8; 32])> = Vec::new();
    for member in staged.members() {
        let handle = match credential_handle(&member.credential) {
            Ok(h) => h,
            Err(e) => {
                provider.rollback_to_disk()?;
                return Err(e);
            }
        };
        if pins.pinned(&handle).is_none() {
            if let Ok(key) = <[u8; 32]>::try_from(member.signature_key.as_slice()) {
                first_contact.push(handle.clone());
                tofu_pins.push((handle, key));
            }
        }
    }

    let group = match staged.into_group(provider) {
        Ok(group) => group,
        Err(e) => {
            provider.rollback_to_disk()?;
            return Err(MlsError::Rejected(format!("welcome finalize: {e:?}")));
        }
    };

    // Success: record the consumed KeyPackageRef(s) durably (REQ-013 step 4 —
    // the durable single-use ledger), pin first-contact members TOFU, then
    // persist (the consumed init key leaves disk here).
    for ref_b64 in &welcome_refs {
        ledger.mark_consumed(ref_b64)?;
    }
    for (handle, key) in tofu_pins {
        pins.observe_verified(&handle, &key)?;
    }
    provider.persist()?;
    Ok(JoinOutcome {
        group,
        genesis,
        trust,
        first_contact_handles: first_contact,
    })
}

/// REQ-012 (b) + (d) over the staged (pre-finalize) tree.
fn validate_staged_welcome(
    staged: &StagedWelcome,
    _room: &str,
    pins: &PinStore,
    joiner_handle: &str,
) -> Result<(), MlsError> {
    // (d) Full-tree leaf-vs-pin: every leaf whose handle is pinned must
    // carry exactly the pinned key; an unpinned key for a pinned handle is a
    // hard reject. Leaves must also advertise the genesis capability
    // (REQ-017's capability clause, checked at the join boundary too).
    let mut bindings: Vec<(String, Vec<u8>)> = Vec::new();
    for member in staged.members() {
        let handle = credential_handle(&member.credential)?;
        if let Some(pin) = pins.pinned(&handle) {
            if member.signature_key != pin.key {
                return Err(MlsError::Rejected(format!(
                    "welcome tree leaf for {handle} does not match the pinned wire key \
                     (REQ-012d hard reject)"
                )));
            }
        }
        bindings.push((handle, member.signature_key.clone()));
    }

    // (b) Authorised committer: the Welcome's sender must be the elected
    // owner of the membership BEFORE this Add — i.e. the delivered tree minus
    // the joiner being added by this commit. This is what makes REQ-016
    // bootstrap work: when the room creator (sole member) adds the first
    // member, the post-Add tree's elected owner may be the newcomer, but the
    // committer's authority comes from owning the *pre-Add* group (just the
    // creator). For a steady-state add the pre-Add set is every prior member,
    // so the current elected owner is the only authorised committer. NOT
    // sufficient alone (circular over a fabricated tree — REQ-012 documents
    // this); (d) is the predicate with teeth, plus the caller's genesis check.
    // (Assumes one joiner per Welcome, which is hark's add flow.)
    let sender = staged
        .welcome_sender()
        .map_err(MlsError::stack("welcome sender"))?;
    let sender_handle = credential_handle(sender.credential())?;
    let sender_key = sender.signature_key().as_slice().to_vec();
    let pre_add: Vec<(String, Vec<u8>)> = bindings
        .iter()
        .filter(|(handle, _)| handle != joiner_handle)
        .cloned()
        .collect();
    // Creator-preferred election over the pre-add roster: the genesis creator
    // (read from the staged group context; the caller separately VERIFIES the
    // genesis signature) is the authorised committer when it is a live pre-add
    // leaf, else the lex-smallest leaf. Mirrors the web crate's elect_committer.
    let genesis_creator = staged
        .group_context()
        .extensions()
        .unknown(GENESIS_EXT_TYPE)
        .and_then(|ext| GenesisAssertion::from_bytes(&ext.0).ok())
        .and_then(|g| g.creator_key().ok().map(|k| (g.creator_handle, k.to_vec())));
    match elect_committer(&pre_add, genesis_creator.as_ref()) {
        Some((owner_handle, owner_key))
            if owner_handle == sender_handle && owner_key == sender_key => {}
        Some((owner_handle, _)) => {
            return Err(MlsError::Rejected(format!(
                "welcome committed by {sender_handle}, but the elected owner of the pre-add \
                 roster is {owner_handle} (REQ-012b)"
            )));
        }
        None => return Err(MlsError::Rejected("welcome tree has no members".into())),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::ChatIdentity;
    use std::fs;
    use std::path::PathBuf;

    struct Party {
        dir: PathBuf,
        provider: DurableProvider,
        identity: MlsIdentity,
        pins: PinStore,
        ledger: ConsumedLedger,
        wire: ChatIdentity,
    }

    fn party(tag: &str, seed: u8, handle: &str) -> Party {
        let dir = std::env::temp_dir().join(format!(
            "hark-mls-group-{tag}-{handle}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let provider = DurableProvider::open(&dir.join("agent.mls")).unwrap();
        let wire = ChatIdentity::from_seed([seed; 32]);
        let identity = MlsIdentity::from_wire_identity(&wire, handle);
        let pins = PinStore::open(&dir.join("agent.pins")).unwrap();
        let ledger = ConsumedLedger::open(&dir.join("agent.kpledger")).unwrap();
        Party {
            dir,
            provider,
            identity,
            pins,
            ledger,
            wire,
        }
    }

    fn pin_each_other(parties: &mut [&mut Party]) {
        let keys: Vec<(String, [u8; 32])> = parties
            .iter()
            .map(|p| (p.identity.handle.clone(), p.wire.verifying_key_bytes()))
            .collect();
        for p in parties.iter_mut() {
            for (handle, key) in &keys {
                p.pins.observe_verified(handle, key).unwrap();
            }
        }
    }

    /// TEST-004 (REQ-004): election is deterministic and order-independent.
    #[test]
    fn election_is_deterministic_over_permutations() {
        let a = ("@alice".to_string(), vec![3u8; 32]);
        let b = ("@bob".to_string(), vec![1u8; 32]);
        let c = ("@carol".to_string(), vec![2u8; 32]);
        let perms: [Vec<(String, Vec<u8>)>; 3] = [
            vec![a.clone(), b.clone(), c.clone()],
            vec![c.clone(), a.clone(), b.clone()],
            vec![b.clone(), c.clone(), a.clone()],
        ];
        for perm in &perms {
            assert_eq!(elect_owner(perm), Some(a.clone()));
        }
        // Tie on handle → key tie-breaker.
        let dup1 = ("@x".to_string(), vec![2u8; 32]);
        let dup2 = ("@x".to_string(), vec![1u8; 32]);
        assert_eq!(elect_owner(&[dup1.clone(), dup2.clone()]), Some(dup2),);
    }

    /// REQ-004/016: creator-preferred election. The genesis creator is the
    /// committer even when a leaf (an agent) sorts lexicographically first; it
    /// falls back to lex-smallest only when the creator is absent or unknown.
    #[test]
    fn elect_committer_prefers_the_genesis_creator() {
        let agent = ("@aaa-agent".to_string(), vec![9u8; 32]); // sorts FIRST
        let creator = ("@person2".to_string(), vec![5u8; 32]); // sorts LAST
        let members = vec![agent.clone(), creator.clone()];

        // Creator present → creator wins despite the agent sorting first.
        assert_eq!(elect_committer(&members, Some(&creator)), Some(creator.clone()));
        // Match is on handle AND key: a creator handle with the wrong key does not win.
        let imposter = ("@person2".to_string(), vec![7u8; 32]);
        assert_eq!(elect_committer(&members, Some(&imposter)), Some(agent.clone()));
        // No creator (genesis-less) → lex-smallest leaf (unchanged behaviour).
        assert_eq!(elect_committer(&members, None), Some(agent.clone()));
        // Creator not a live leaf (left the group) → fall back to lex-smallest.
        let gone = ("@zzz-gone".to_string(), vec![1u8; 32]);
        assert_eq!(elect_committer(&members, Some(&gone)), Some(agent));
    }

    /// K-2 (REQ-016): a default-capability creator of a genesis-bearing
    /// group — which openmls accepts and then bricks at the first
    /// path-commit (§10 method note) — is refused by the guard at creation
    /// time, before the first real Commit.
    #[test]
    fn k2_guard_rejects_capability_free_creator() {
        let omitted = party("k2", 30, "@alice");
        let extensions = Extensions::single(Extension::Unknown(
            GENESIS_EXT_TYPE,
            UnknownExtension(b"genesis".to_vec()),
        ))
        .unwrap();
        let config = MlsGroupCreateConfig::builder()
            .use_ratchet_tree_extension(true)
            .ciphersuite(CIPHERSUITE)
            .with_group_context_extensions(extensions)
            .build(); // note: NO genesis capability — the §10 brick shape
        let doomed = MlsGroup::new(
            &omitted.provider,
            &omitted.identity.signer,
            &config,
            omitted.identity.credential.clone(),
        )
        .expect("openmls accepts the doomed creator (the trap K-2 closes)");
        let err = assert_creator_capability(&doomed).unwrap_err();
        assert!(matches!(err, MlsError::Rejected(_)));

        // And the supported path always passes the guard.
        let ok = party("k2ok", 29, "@alice");
        let (group, _genesis) = create_group(&ok.provider, &ok.identity, "@research").unwrap();
        assert_creator_capability(&group).unwrap();
        let _ = fs::remove_dir_all(&omitted.dir);
        let _ = fs::remove_dir_all(&ok.dir);
    }

    /// TEST-001/TEST-003/TEST-016: create → add (REQ-008-verified) →
    /// welcome → join (REQ-012-validated) round trip with the genesis
    /// readable pre-finalize and the trust graded by pins.
    /// SPEC-027 REQ-001 — **the gate refuses a promise that does not cover this
    /// merge**, and this is the case the epoch check exists for.
    ///
    /// A committer arms at epoch N. Before it merges, another member's Commit
    /// lands (or a reconnect replays history) and the group moves to N+1. The
    /// armed claim is genuine, held, and for the wrong epoch — merging on it is
    /// merging on a promise nobody made about this state. Without the re-check
    /// this reads as compliance: the claim is armed, so the flag says go.
    #[test]
    fn a_promise_for_another_epoch_does_not_authorise_this_merge() {
        use crate::mls::claim::{ArmedClaim, ClaimState, CommitPromise, Grant};

        let armed_at_9 = ArmedClaim::from_grant(
            &Grant {
                epoch: 9,
                token: "tok".to_owned(),
                state: ClaimState::Armed,
            },
            "@research",
        )
        .expect("armed");

        // The group is at epoch 0; the promise is for 9.
        let err = check_promise(&CommitPromise::Armed(&armed_at_9), "@research", 0)
            .expect_err("a promise for another epoch must not authorise the merge");
        let text = err.to_string();
        assert!(
            text.contains("epoch 9") && text.contains("REQ-001"),
            "the refusal names the epoch the promise covers, so an operator can \
             see it is a sequencing problem and not a permissions one: {text}"
        );

        // The same promise at its own epoch is fine.
        check_promise(&CommitPromise::Armed(&armed_at_9), "@research", 9)
            .expect("the promise authorises its own epoch");
        // And another room's merge is not covered either.
        check_promise(&CommitPromise::Armed(&armed_at_9), "@other", 9)
            .expect_err("a promise for another room is not a promise for this one");
        // An unactivated room commits as before — the status quo, not a hole.
        check_promise(&CommitPromise::Inactive, "@research", 0)
            .expect("an inactive room commits unclaimed, as it did before SPEC-063");
    }

    /// SPEC-027 REQ-001 — the gate is reached from `add_member` itself, not
    /// merely available beside it.
    ///
    /// Every call site currently passes `Inactive`, which is a no-op, so a
    /// `check_promise` unit test alone cannot tell whether `add_member` calls
    /// it. Removing the call passed that suite. This drives a real Add with a
    /// genuine armed claim for the *wrong* epoch and requires the refusal.
    #[test]
    fn add_member_itself_refuses_a_promise_for_another_epoch() {
        use crate::mls::claim::{ArmedClaim, ClaimState, CommitPromise, Grant};

        let mut alice = party("gate-add", 71, "@alice");
        let mut bob = party("gate-add", 72, "@bob");
        pin_each_other(&mut [&mut alice, &mut bob]);
        let (mut group, _genesis) =
            create_group(&alice.provider, &alice.identity, "@research").unwrap();
        let kp = super::super::keypackages::build_one_time(&bob.provider, &bob.identity, 1)
            .unwrap()
            .remove(0);

        // Armed — but for an epoch this group is not at.
        let stale = ArmedClaim::from_grant(
            &Grant {
                epoch: 99,
                token: "tok".to_owned(),
                state: ClaimState::Armed,
            },
            "@research",
        )
        .expect("armed");

        let err = add_member(
            &alice.provider,
            &alice.identity,
            &mut group,
            &kp.bytes,
            "@bob",
            &alice.pins,
            &mut alice.ledger,
            "@research",
            CommitPromise::Armed(&stale),
        )
        .err()
        .expect("a promise for another epoch must not authorise this Add");
        assert!(
            err.to_string().contains("REQ-001"),
            "and the refusal says why: {err}"
        );

        // Nothing was generated or merged: the group is where it was.
        assert_eq!(
            group.epoch().as_u64(),
            0,
            "a refused promise must leave the group untouched — the whole point \
             is that state does not move without one"
        );
    }

    /// A room created by `@alice`, with `@bob` admitted by Welcome (so Bob holds
    /// a leaf but is not the creator and cannot commit Adds), and the GroupInfo
    /// the hub would serve for it.
    struct PairedRoom {
        alice: Party,
        bob: Party,
        group: MlsGroup,
        bob_group: MlsGroup,
        genesis: GenesisAssertion,
        gi: Vec<u8>,
    }

    fn paired_room(tag: &str, seeds: (u8, u8)) -> PairedRoom {
        use openmls_traits::OpenMlsProvider as _;
        let mut alice = party(tag, seeds.0, "@alice");
        let mut bob = party(tag, seeds.1, "@bob");
        pin_each_other(&mut [&mut alice, &mut bob]);
        let (mut group, genesis) =
            create_group(&alice.provider, &alice.identity, "@research").unwrap();
        let kp = super::super::keypackages::build_one_time(&bob.provider, &bob.identity, 1)
            .unwrap()
            .remove(0);
        let outcome = add_member(
            &alice.provider,
            &alice.identity,
            &mut group,
            &kp.bytes,
            "@bob",
            &alice.pins,
            &mut alice.ledger,
            "@research",
            crate::mls::claim::CommitPromise::Inactive,
        )
        .unwrap();
        let bob_group = join_from_welcome(
            &bob.provider,
            &bob.identity,
            &outcome.welcome_bytes,
            "@research",
            &mut bob.pins,
            &mut bob.ledger,
            None,
        )
        .unwrap()
        .group;
        assert_eq!(group.members().count(), 2);
        let gi = group
            .export_group_info(alice.provider.crypto(), &alice.identity.signer, true)
            .unwrap()
            .tls_serialize_detached()
            .unwrap();
        PairedRoom {
            alice,
            bob,
            group,
            bob_group,
            genesis,
            gi,
        }
    }

    /// Bytes of a party's durable files, to prove a refusal wrote nothing.
    fn durable_state(p: &Party) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
        (
            fs::read(p.dir.join("agent.mls")).ok(),
            fs::read(p.dir.join("agent.pins")).ok(),
        )
    }

    /// The in-memory pins for every handle these fixtures use.
    fn pin_snapshot(pins: &PinStore) -> Vec<Option<([u8; 32], bool)>> {
        ["@alice", "@bob", "@mallory", "@agent6"]
            .iter()
            .map(|h| pins.pinned(h).map(|p| (p.key, p.flagged)))
            .collect()
    }

    /// The group id a GroupInfo describes, read without joining it.
    fn group_info_group_id(gi: &[u8]) -> Vec<u8> {
        let msg = MlsMessageIn::tls_deserialize_exact_bytes(gi).unwrap();
        let MlsMessageBodyIn::GroupInfo(vgi) = msg.extract() else {
            panic!("a GroupInfo")
        };
        vgi.group_id().as_slice().to_vec()
    }

    /// The JOINER refuses: nothing installed in memory, nothing persisted, no pin
    /// written, no Commit to hand to anyone. Returns the refusal.
    fn joiner_refuses(joiner: &mut Party, gi: &[u8], grant: &str, now_ms: u64, why: &str) -> String {
        let before = durable_state(joiner);
        let pinned_before = pin_snapshot(&joiner.pins);
        let err = match join_by_grant(
            &joiner.provider,
            &joiner.identity,
            gi,
            "@research",
            grant,
            &mut joiner.pins,
            now_ms,
        ) {
            Ok(_) => panic!("the joiner installed a group it must refuse: {why}"),
            Err(e) => e.to_string(),
        };
        let gid = GroupId::from_slice(&group_info_group_id(gi));
        assert!(
            MlsGroup::load(joiner.provider.storage(), &gid).unwrap().is_none(),
            "a refused GroupInfo must leave no group in the provider: {why}"
        );
        assert_eq!(durable_state(joiner), before, "a refusal must persist nothing: {why}");
        assert_eq!(pin_snapshot(&joiner.pins), pinned_before, "a refusal must pin nothing: {why}");
        err
    }

    /// The MEMBER refuses an external Commit built (unverified) on `grant`, before
    /// merging it.
    fn member_refuses(room: &mut PairedRoom, joiner: &Party, grant: &str, why: &str) -> String {
        let built = build_external_join(
            &joiner.provider,
            &joiner.identity,
            &room.gi,
            "@research",
            grant,
            &joiner.pins,
        )
        .expect("the unverified builder always builds; the refusal is the member's");
        let mut fork = crate::mls::validation::ForkSignal::default();
        let err = crate::mls::validation::process_inbound(
            &room.alice.provider,
            &mut room.group,
            &built.commit,
            "@research",
            &mut room.alice.pins,
            &room.genesis,
            None,
            &mut fork,
            false,
        )
        .err()
        .unwrap_or_else(|| panic!("the member merged a Commit it must refuse: {why}"));
        drop(built);
        joiner.provider.rollback_to_disk().unwrap();
        assert_eq!(room.group.members().count(), 2, "a refusal must not seat anyone: {why}");
        err.to_string()
    }

    /// SPEC-061 REQ-008 / TEST-014 + TEST-015: an agent seats itself on a grant
    /// signed by a member that is NOT the creator, and is refused every other way —
    /// by the joiner before it installs anything, AND by the member before merge.
    ///
    /// This is the production failure, in one function. `@bob` joined by
    /// invitation, so it holds a leaf and cannot commit; it pairs an agent and
    /// signs for it from the group it holds; `@alice`, who created the channel, is
    /// not consulted and does not have to be online. The agent has pinned only
    /// Bob, so `@alice`'s genesis is first contact (TOFU) — the legitimate
    /// first-contact, non-creator pairing that group binding must preserve.
    #[test]
    fn a_member_authorises_an_agent_that_seats_itself() {
        const EXP: u64 = 1_800_000_000_000 + 86_400_000;
        let now = crate::mls::validation::now_ms();
        assert!(now < EXP, "the fixture's expiry must be in the future of the wall clock");

        let mut room = paired_room("pg", (41, 42));
        let mut agent = party("pg", 43, "@agent6");
        let mallory = party("pg", 44, "@mallory");
        // Same HANDLE as the agent, a different key: a hub that read the grant.
        let mut impostor = party("pg-i", 45, "@agent6");
        let bob_key = room.bob.wire.verifying_key_bytes();
        agent.pins.observe_verified("@bob", &bob_key).unwrap();
        impostor.pins.observe_verified("@bob", &bob_key).unwrap();
        let gid = room.group.group_id().as_slice().to_vec();
        assert_eq!(room.bob_group.group_id().as_slice(), gid.as_slice());

        let agent_key = agent.wire.verifying_key_bytes();
        let good = serde_json::to_string(&PairingGrant::mint(
            &room.bob.wire,
            "@bob",
            &bob_key,
            &room.bob_group,
            "@research",
            "@agent6",
            &agent_key,
            EXP,
        ))
        .unwrap();
        assert!(good.contains(&format!("\"group_id_b64\":\"{}\"", B64.encode(&gid))));

        // 1. The signer holds no leaf. A real key, a real signature, the right
        //    group id — no seat.
        let outsider = serde_json::to_string(&PairingGrant::mint_for_group_id(
            &mallory.wire,
            "@mallory",
            &mallory.wire.verifying_key_bytes(),
            &gid,
            "@research",
            "@agent6",
            &agent_key,
            EXP,
        ))
        .unwrap();
        let e = joiner_refuses(&mut agent, &room.gi, &outsider, now, "non-member signer");
        assert!(e.contains("not a live leaf"), "{e}");
        let e = member_refuses(&mut room, &agent, &outsider, "non-member signer");
        assert!(e.contains("not a live leaf"), "{e}");

        // 2. The signer handle lifted onto another live member, key and all. The
        //    live-leaf check passes — @alice IS one — so this reaches the
        //    signature, which is why both handles are inside the signed bytes.
        let lifted = good
            .replace("\"signer_handle\":\"@bob\"", "\"signer_handle\":\"@alice\"")
            .replace(
                &format!("\"signer_key_b64\":\"{}\"", B64.encode(bob_key)),
                &format!(
                    "\"signer_key_b64\":\"{}\"",
                    B64.encode(room.alice.wire.verifying_key_bytes())
                ),
            );
        assert!(lifted.contains("@alice"), "the fixture must actually be rewritten");
        let e = joiner_refuses(&mut agent, &room.gi, &lifted, now, "re-pointed signer");
        assert!(e.contains("does not verify"), "{e}");
        let e = member_refuses(&mut room, &agent, &lifted, "re-pointed signer");
        assert!(e.contains("does not verify"), "{e}");

        // 3. The right handle, the wrong key — a party that READ the grant and
        //    tried to use it. This is the case cleartext carriage rests on.
        let e = joiner_refuses(&mut impostor, &room.gi, &good, now, "subject key mismatch");
        assert!(e.contains("different key"), "{e}");
        let e = member_refuses(&mut room, &impostor, &good, "subject key mismatch");
        assert!(e.contains("different key"), "{e}");

        // 4. Expired. A real past instant: the member reads the wall clock.
        let stale = serde_json::to_string(&PairingGrant::mint(
            &room.bob.wire,
            "@bob",
            &bob_key,
            &room.bob_group,
            "@research",
            "@agent6",
            &agent_key,
            1, // 1970
        ))
        .unwrap();
        let e = joiner_refuses(&mut agent, &room.gi, &stale, now, "expired");
        assert!(e.contains("expired"), "{e}");
        let e = member_refuses(&mut room, &agent, &stale, "expired");
        assert!(e.contains("expired"), "{e}");

        // 5. Forged: the right fields, a signature that is not Bob's over them.
        let mut forged: PairingGrant = serde_json::from_str(&good).unwrap();
        let mut sig = B64.decode(&forged.sig_b64).unwrap();
        sig[0] ^= 0x01;
        forged.sig_b64 = B64.encode(sig);
        let forged = serde_json::to_string(&forged).unwrap();
        let e = joiner_refuses(&mut agent, &room.gi, &forged, now, "forged signature");
        assert!(e.contains("does not verify"), "{e}");
        let e = member_refuses(&mut room, &agent, &forged, "forged signature");
        assert!(e.contains("does not verify"), "{e}");

        // …and the one that must work: first contact with the creator, a
        // non-creator signer, the genuine group.
        let join = join_by_grant(
            &agent.provider,
            &agent.identity,
            &room.gi,
            "@research",
            &good,
            &mut agent.pins,
            now,
        )
        .expect("the agent seats itself");
        assert_eq!(join.genesis, room.genesis, "and on the room's own genesis");
        assert_eq!(
            join.trust,
            GenesisTrust::TofuRequiresSafetyNumber,
            "first contact with the creator stays TOFU — pairing does not need a creator pin"
        );
        let mut fork = crate::mls::validation::ForkSignal::default();
        crate::mls::validation::process_inbound(
            &room.alice.provider,
            &mut room.group,
            &join.commit,
            "@research",
            &mut room.alice.pins,
            &room.genesis,
            None,
            &mut fork,
            false,
        )
        .expect("the member admits it");
        assert_eq!(room.group.members().count(), 3, "the agent is a live leaf now");
    }

    /// THE reproduced authority gap (cbcl-bus
    /// `external-admission-unanchored-pairing.test.mjs`, natively): Mallory takes
    /// another public KeyPackage of Bob's and Adds that leaf to a RIVAL group she
    /// creates under the SAME room name; Bob never processes her Welcome. The agent
    /// pinned Bob's genuine key. Mallory's GroupInfo then has a self-signed,
    /// unpinned genesis (TOFU), a live `@bob` leaf carrying exactly the pinned key,
    /// and the agent holds Bob's genuine, unexpired grant naming it — which under
    /// v1 satisfied every check. v2 binds the grant to Bob's real group, so the
    /// UNCHANGED grant is refused against the rival before anything is installed,
    /// and still seats the agent in the genuine group afterwards.
    #[test]
    fn a_rival_same_room_group_info_with_the_signers_copied_leaf_is_refused() {
        let now = crate::mls::validation::now_ms();
        let exp = now + 86_400_000;
        let mut room = paired_room("rival", (51, 52));
        let mut agent = party("rival", 53, "@agent6");
        let mut mallory = party("rival", 54, "@mallory");
        let bob_key = room.bob.wire.verifying_key_bytes();
        agent.pins.observe_verified("@bob", &bob_key).unwrap();

        // Bob's genuine v2 grant, minted from the group he actually holds.
        let good = serde_json::to_string(&PairingGrant::mint(
            &room.bob.wire,
            "@bob",
            &bob_key,
            &room.bob_group,
            "@research",
            "@agent6",
            &agent.wire.verifying_key_bytes(),
            exp,
        ))
        .unwrap();

        // Mallory's rival: same room name, her own genesis, Bob's public leaf.
        mallory.pins.observe_verified("@bob", &bob_key).unwrap();
        let (mut rival, rival_genesis) =
            create_group(&mallory.provider, &mallory.identity, "@research").unwrap();
        let bob_kp = super::super::keypackages::build_one_time(&room.bob.provider, &room.bob.identity, 1)
            .unwrap()
            .remove(0);
        add_member(
            &mallory.provider,
            &mallory.identity,
            &mut rival,
            &bob_kp.bytes,
            "@bob",
            &mallory.pins,
            &mut mallory.ledger,
            "@research",
            crate::mls::claim::CommitPromise::Inactive,
        )
        .expect("anyone holding Bob's public KeyPackage can seat a copy of his leaf");
        let rival_gi = {
            use openmls_traits::OpenMlsProvider as _;
            rival
                .export_group_info(mallory.provider.crypto(), &mallory.identity.signer, true)
                .unwrap()
                .tls_serialize_detached()
                .unwrap()
        };

        // Preconditions that make this the real attack, not a strawman: the rival
        // is the same room, its genesis grades TOFU (no conflicting pin for the
        // agent to catch), and its `@bob` leaf IS Bob's genuine pinned key.
        assert_eq!(rival_genesis.room, "@research");
        assert_ne!(rival.group_id().as_slice(), room.group.group_id().as_slice());
        assert_eq!(
            rival_genesis
                .verify("@research", rival.group_id().as_slice(), &agent.pins)
                .unwrap(),
            GenesisTrust::TofuRequiresSafetyNumber
        );
        let rival_bob: Vec<_> = rival
            .members()
            .filter(|m| credential_handle(&m.credential).unwrap() == "@bob")
            .collect();
        assert_eq!(rival_bob.len(), 1);
        assert_eq!(rival_bob[0].signature_key, bob_key.to_vec());

        let e = joiner_refuses(&mut agent, &rival_gi, &good, now, "rival same-room GroupInfo");
        assert!(e.contains("different MLS group"), "{e}");

        // The refusal spent nothing: the same grant still seats the agent in the
        // group Bob actually holds, and the member admits it.
        let join = join_by_grant(
            &agent.provider,
            &agent.identity,
            &room.gi,
            "@research",
            &good,
            &mut agent.pins,
            now,
        )
        .expect("the genuine group still admits the agent");
        let mut fork = crate::mls::validation::ForkSignal::default();
        crate::mls::validation::process_inbound(
            &room.alice.provider,
            &mut room.group,
            &join.commit,
            "@research",
            &mut room.alice.pins,
            &room.genesis,
            None,
            &mut fork,
            false,
        )
        .expect("the member admits it");
        assert_eq!(room.group.members().count(), 3);
    }

    /// A grant genuinely signed by a live member for ANOTHER group id is refused
    /// by the joiner and by the member: the group id is inside the signature, and
    /// rewriting `group_id_b64` to match breaks it.
    #[test]
    fn a_grant_for_another_group_is_refused_by_joiner_and_member() {
        let now = crate::mls::validation::now_ms();
        let exp = now + 86_400_000;
        let mut room = paired_room("wronggroup", (61, 62));
        let mut agent = party("wronggroup", 63, "@agent6");
        let bob_key = room.bob.wire.verifying_key_bytes();
        let agent_key = agent.wire.verifying_key_bytes();
        let gid = room.group.group_id().as_slice().to_vec();
        let mut other = gid.clone();
        other[31] ^= 0xFF;

        let wrong = serde_json::to_string(&PairingGrant::mint_for_group_id(
            &room.bob.wire, "@bob", &bob_key, &other, "@research", "@agent6", &agent_key, exp,
        ))
        .unwrap();
        let e = joiner_refuses(&mut agent, &room.gi, &wrong, now, "wrong group");
        assert!(e.contains("different MLS group"), "{e}");
        let e = member_refuses(&mut room, &agent, &wrong, "wrong group");
        assert!(e.contains("different MLS group"), "{e}");

        // Relabelled: `group_id_b64` rewritten to this group, signature unchanged.
        let relabelled = wrong.replace(
            &format!("\"group_id_b64\":\"{}\"", B64.encode(&other)),
            &format!("\"group_id_b64\":\"{}\"", B64.encode(&gid)),
        );
        assert_ne!(relabelled, wrong, "the fixture must actually be rewritten");
        let e = joiner_refuses(&mut agent, &room.gi, &relabelled, now, "relabelled group");
        assert!(e.contains("does not verify"), "{e}");
        let e = member_refuses(&mut room, &agent, &relabelled, "relabelled group");
        assert!(e.contains("does not verify"), "{e}");
    }

    /// v1 grants, unknown kinds and malformed v2 records are refused on both
    /// sides — and never re-read as an invite grant (the error is the pairing
    /// dispatch's, not the invite parser's or the invite signature's).
    #[test]
    fn old_unknown_and_malformed_pairing_records_are_refused_not_routed_to_invite() {
        let now = crate::mls::validation::now_ms();
        let exp = now + 86_400_000;
        let mut room = paired_room("v1", (71, 72));
        let mut agent = party("v1", 73, "@agent6");
        let bob_key = room.bob.wire.verifying_key_bytes();
        let agent_key = agent.wire.verifying_key_bytes();

        // A genuine v1 grant: the v1 label and layout (no group), signed by Bob.
        let mut v1_signed = Vec::new();
        lp(&mut v1_signed, b"cbcl-mls-pairgrant/v1");
        lp(&mut v1_signed, b"@research");
        lp(&mut v1_signed, b"@bob");
        lp(&mut v1_signed, &bob_key);
        lp(&mut v1_signed, b"@agent6");
        lp(&mut v1_signed, &agent_key);
        v1_signed.extend_from_slice(&exp.to_be_bytes());
        let v1 = serde_json::json!({
            "kind": "cbcl-mls-pairgrant/v1",
            "room": "@research",
            "signer_handle": "@bob",
            "signer_key_b64": B64.encode(bob_key),
            "subject_handle": "@agent6",
            "subject_key_b64": B64.encode(agent_key),
            "not_after_ms": exp,
            "sig_b64": B64.encode(room.bob.wire.sign(&v1_signed)),
        })
        .to_string();
        let e = joiner_refuses(&mut agent, &room.gi, &v1, now, "v1 grant");
        assert!(e.contains("not supported") && e.contains("never re-read as an invite"), "{e}");
        let e = member_refuses(&mut room, &agent, &v1, "v1 grant");
        assert!(e.contains("not supported") && e.contains("never re-read as an invite"), "{e}");

        // A future/unknown version and a non-string kind: same refusal.
        let v3 = v1.replace("cbcl-mls-pairgrant/v1", "cbcl-mls-pairgrant/v3");
        let e = joiner_refuses(&mut agent, &room.gi, &v3, now, "unknown kind");
        assert!(e.contains("not supported"), "{e}");
        let nonstring = v1.replace("\"cbcl-mls-pairgrant/v1\"", "7");
        let e = member_refuses(&mut room, &agent, &nonstring, "non-string kind");
        assert!(e.contains("not supported"), "{e}");

        // v2 kind on a v1-shaped record: `group_id_b64` is required.
        let v2_no_group = v1.replace("cbcl-mls-pairgrant/v1", "cbcl-mls-pairgrant/v2");
        let e = joiner_refuses(&mut agent, &room.gi, &v2_no_group, now, "v2 without group");
        assert!(e.contains("pairing grant json") && e.contains("group_id_b64"), "{e}");
        let e = member_refuses(&mut room, &agent, &v2_no_group, "v2 without group");
        assert!(e.contains("pairing grant json") && e.contains("group_id_b64"), "{e}");

        // A genuine v2 grant with one extra key: the record is closed.
        let good = serde_json::to_string(&PairingGrant::mint(
            &room.bob.wire, "@bob", &bob_key, &room.bob_group, "@research", "@agent6",
            &agent_key, exp,
        ))
        .unwrap();
        let extra = good.replacen('{', "{\"creator_handle\":\"@alice\",", 1);
        let e = joiner_refuses(&mut agent, &room.gi, &extra, now, "unknown field");
        assert!(e.contains("unknown field"), "{e}");
        let e = member_refuses(&mut room, &agent, &extra, "unknown field");
        assert!(e.contains("unknown field"), "{e}");
    }

    /// The joiner's own REQ-016 / REQ-012d checks on the GroupInfo, with a grant
    /// that is otherwise perfect: a creator that conflicts with a pin, and a tree
    /// leaf that conflicts with a pin, both refuse with nothing installed.
    #[test]
    fn joiner_refuses_group_info_conflicting_with_its_pins() {
        let now = crate::mls::validation::now_ms();
        let exp = now + 86_400_000;
        let room = paired_room("joinpins", (81, 82));
        let bob_key = room.bob.wire.verifying_key_bytes();
        let stranger = ChatIdentity::from_seed([0xEE; 32]).verifying_key_bytes();

        // The creator is pinned to a different key.
        let mut agent = party("joinpins-c", 83, "@agent6");
        agent.pins.observe_verified("@alice", &stranger).unwrap();
        let good = serde_json::to_string(&PairingGrant::mint(
            &room.bob.wire, "@bob", &bob_key, &room.bob_group, "@research", "@agent6",
            &agent.wire.verifying_key_bytes(), exp,
        ))
        .unwrap();
        let e = joiner_refuses(&mut agent, &room.gi, &good, now, "creator pin conflict");
        assert!(e.contains("conflicts with the pinned wire key"), "{e}");

        // A non-creator leaf (the signer) is pinned to a different key.
        let mut agent = party("joinpins-t", 83, "@agent6");
        agent.pins.observe_verified("@bob", &stranger).unwrap();
        let e = joiner_refuses(&mut agent, &room.gi, &good, now, "tree pin conflict");
        assert!(e.contains("REQ-012d"), "{e}");

        // Wrong room for the GroupInfo's genesis.
        let mut agent = party("joinpins-r", 83, "@agent6");
        let before = durable_state(&agent);
        let e = join_by_grant(
            &agent.provider, &agent.identity, &room.gi, "@elsewhere", &good, &mut agent.pins, now,
        )
        .err()
        .expect("a GroupInfo for another room is refused")
        .to_string();
        assert!(e.contains("genesis bound to room"), "{e}");
        assert_eq!(durable_state(&agent), before);
    }

    #[test]
    fn create_add_join_roundtrip_with_genesis() {
        let mut alice = party("rt", 31, "@alice");
        let mut bob = party("rt", 32, "@bob");
        pin_each_other(&mut [&mut alice, &mut bob]);

        let (mut group, genesis) =
            create_group(&alice.provider, &alice.identity, "@research").unwrap();
        assert_eq!(
            genesis
                .verify("@research", group.group_id().as_slice(), &alice.pins)
                .unwrap(),
            GenesisTrust::Authoritative,
        );

        // Bob publishes; Alice (owner) adds him after REQ-008 verification.
        let kp = super::super::keypackages::build_one_time(&bob.provider, &bob.identity, 1)
            .unwrap()
            .remove(0);
        let outcome = add_member(
            &alice.provider,
            &alice.identity,
            &mut group,
            &kp.bytes,
            "@bob",
            &alice.pins,
            &mut alice.ledger,
        
            "@research",
            crate::mls::claim::CommitPromise::Inactive,
        )
        .unwrap();

        // Bob joins; genesis is authoritative because Alice's key is pinned.
        let joined = join_from_welcome(
            &bob.provider,
            &bob.identity,
            &outcome.welcome_bytes,
            "@research",
            &mut bob.pins,
            &mut bob.ledger,
            None,
        )
        .unwrap();
        assert_eq!(joined.trust, GenesisTrust::Authoritative);
        assert_eq!(joined.genesis, genesis);
        assert_eq!(joined.group.members().count(), 2);
        assert!(joined.first_contact_handles.is_empty());

        // REQ-013: a successful join records the consumed KeyPackageRef in the
        // DURABLE ledger (regression: this loop was previously dead, leaving
        // the single-use ledger permanently empty). Reopen it to prove it
        // persisted, and that a replayed Welcome to that ref is now rejected.
        let ledger =
            super::super::keypackages::ConsumedLedger::open(&bob.dir.join("agent.kpledger"))
                .unwrap();
        assert!(
            bob.dir.join("agent.kpledger").exists(),
            "join must persist the consumed-ref ledger"
        );
        let replay = join_from_welcome(
            &bob.provider,
            &bob.identity,
            &outcome.welcome_bytes,
            "@research",
            &mut bob.pins,
            &mut { ledger },
            None,
        );
        assert!(
            replay.is_err(),
            "a replayed Welcome to a consumed ref is rejected (REQ-013)"
        );

        // Integrity guard: the owner refuses to add @bob a second time (an
        // unsolicited/replayed keypkg for an existing member must not seat a
        // duplicate leaf).
        let kp2 = super::super::keypackages::build_one_time(&bob.provider, &bob.identity, 1)
            .unwrap()
            .remove(0);
        let dup = add_member(
            &alice.provider,
            &alice.identity,
            &mut group,
            &kp2.bytes,
            "@bob",
            &alice.pins,
            &mut alice.ledger,
        
            "@research",
            crate::mls::claim::CommitPromise::Inactive,
        );
        assert!(
            matches!(&dup, Err(MlsError::Rejected(m)) if m.contains("already a member")),
            "duplicate-leaf Add must be rejected, got {}",
            dup.map(|_| "Ok").unwrap_or("other Err")
        );

        let _ = fs::remove_dir_all(&alice.dir);
        let _ = fs::remove_dir_all(&bob.dir);
    }

    /// TEST-008 (REQ-008): a KeyPackage for the wrong handle, or whose leaf
    /// key is not the target's pinned wire key, is rejected; an unpinned
    /// target is also rejected (hub-asserted keys are never enough).
    #[test]
    fn adder_verification_rejects_wrong_target_and_unpinned_keys() {
        let mut alice = party("req008", 33, "@alice");
        let mut bob = party("req008", 34, "@bob");
        let mut mallory = party("req008", 35, "@mallory");

        // Mallory crafts a package CLAIMING to be @bob (handle string) but
        // carrying her own key.
        let forged_identity = MlsIdentity::from_wire_identity(&mallory.wire, "@bob");
        let forged =
            super::super::keypackages::build_one_time(&mallory.provider, &forged_identity, 1)
                .unwrap()
                .remove(0);

        pin_each_other(&mut [&mut alice, &mut bob, &mut mallory]);
        let (mut group, _genesis) =
            create_group(&alice.provider, &alice.identity, "@research").unwrap();

        // (a) wrong handle: package says @mallory, target is @bob.
        let mallory_kp =
            super::super::keypackages::build_one_time(&mallory.provider, &mallory.identity, 1)
                .unwrap()
                .remove(0);
        assert!(
            add_member(
                &alice.provider,
                &alice.identity,
                &mut group,
                &mallory_kp.bytes,
                "@bob",
                &alice.pins,
                &mut alice.ledger,
            
            "@research",
            crate::mls::claim::CommitPromise::Inactive,
        )
            .is_err(),
            "credential identity must match the intended target"
        );

        // (b) right handle, wrong key: forged @bob package with Mallory's key.
        assert!(
            add_member(
                &alice.provider,
                &alice.identity,
                &mut group,
                &forged.bytes,
                "@bob",
                &alice.pins,
                &mut alice.ledger,
            
            "@research",
            crate::mls::claim::CommitPromise::Inactive,
        )
            .is_err(),
            "leaf key must equal the pinned wire key"
        );

        let _ = fs::remove_dir_all(&alice.dir);
        let _ = fs::remove_dir_all(&bob.dir);
        let _ = fs::remove_dir_all(&mallory.dir);
    }

    /// TEST-012 (REQ-012d + REQ-013): a Welcome whose tree binds a pinned
    /// handle to a different key is hard-rejected — and the rejection leaves
    /// the one-time init key intact, so the honest Welcome still joins.
    #[test]
    fn pin_violating_welcome_rejected_and_init_key_survives() {
        let mut alice = party("d", 36, "@alice");
        let mut bob = party("d", 37, "@bob");
        let mut mallory = party("d", 38, "@mallory");

        // Bob pins the REAL alice key…
        pin_each_other(&mut [&mut alice, &mut bob]);
        // …and mallory knows bob's key (to add him).
        mallory
            .pins
            .observe_verified("@bob", &bob.wire.verifying_key_bytes())
            .unwrap();

        // Mallory stands up a rival group impersonating @alice.
        let fake_alice = MlsIdentity::from_wire_identity(&mallory.wire, "@alice");
        let (mut fake_group, _g) =
            create_group(&mallory.provider, &fake_alice, "@research").unwrap();

        let kp = super::super::keypackages::build_one_time(&bob.provider, &bob.identity, 1)
            .unwrap()
            .remove(0);
        let fake_outcome = add_member(
            &mallory.provider,
            &fake_alice,
            &mut fake_group,
            &kp.bytes,
            "@bob",
            &mallory.pins,
            &mut mallory.ledger,
        
            "@research",
            crate::mls::claim::CommitPromise::Inactive,
        )
        .unwrap();

        // Bob rejects: the tree's @alice leaf does not match his pin.
        let Err(err) = join_from_welcome(
            &bob.provider,
            &bob.identity,
            &fake_outcome.welcome_bytes,
            "@research",
            &mut bob.pins,
            &mut bob.ledger,
            None,
        ) else {
            panic!("pin-violating welcome must reject");
        };
        assert!(matches!(err, MlsError::Rejected(_)), "{err}");

        // REQ-013: the junk Welcome did NOT burn Bob's init key — the honest
        // committer's Welcome to the SAME package still joins.
        let (mut group, _genesis) =
            create_group(&alice.provider, &alice.identity, "@research").unwrap();
        let honest = add_member(
            &alice.provider,
            &alice.identity,
            &mut group,
            &kp.bytes,
            "@bob",
            &alice.pins,
            &mut alice.ledger,
        
            "@research",
            crate::mls::claim::CommitPromise::Inactive,
        )
        .unwrap();
        join_from_welcome(
            &bob.provider,
            &bob.identity,
            &honest.welcome_bytes,
            "@research",
            &mut bob.pins,
            &mut bob.ledger,
            None,
        )
        .expect("honest welcome must still join after the junk one was rejected");

        let _ = fs::remove_dir_all(&alice.dir);
        let _ = fs::remove_dir_all(&bob.dir);
        let _ = fs::remove_dir_all(&mallory.dir);
    }

    /// REQ-012 (a)+(c): a Welcome for another room is rejected via its
    /// genesis binding; an existing group refuses silent replacement; a
    /// genesis whose creator key conflicts with a pinned handle is rejected.
    #[test]
    fn wrong_room_existing_group_and_conflicting_genesis_rejected() {
        let mut alice = party("abc", 39, "@alice");
        let mut bob = party("abc", 40, "@bob");
        pin_each_other(&mut [&mut alice, &mut bob]);

        let (mut group, _genesis) =
            create_group(&alice.provider, &alice.identity, "@research").unwrap();
        let kp = super::super::keypackages::build_one_time(&bob.provider, &bob.identity, 1)
            .unwrap()
            .remove(0);
        let outcome = add_member(
            &alice.provider,
            &alice.identity,
            &mut group,
            &kp.bytes,
            "@bob",
            &alice.pins,
            &mut alice.ledger,
        
            "@research",
            crate::mls::claim::CommitPromise::Inactive,
        )
        .unwrap();

        // (a) Wrong room: bob is joining @other, the genesis says @research.
        let Err(err) = join_from_welcome(
            &bob.provider,
            &bob.identity,
            &outcome.welcome_bytes,
            "@other",
            &mut bob.pins,
            &mut bob.ledger,
            None,
        ) else {
            panic!("wrong-room welcome must reject");
        };
        assert!(matches!(err, MlsError::Rejected(_)));

        // (c) Existing group: refuses silent replacement.
        let Err(err) = join_from_welcome(
            &bob.provider,
            &bob.identity,
            &outcome.welcome_bytes,
            "@research",
            &mut bob.pins,
            &mut bob.ledger,
            Some(b"existing-group-id"),
        ) else {
            panic!("existing group must refuse replacement");
        };
        assert!(matches!(err, MlsError::Rejected(_)));

        let _ = fs::remove_dir_all(&alice.dir);
        let _ = fs::remove_dir_all(&bob.dir);
    }

    /// REQ-016: an all-first-contact tree joins as TOFU and reports the
    /// first-contact handles (the caller must require safety-number
    /// confirmation before treating the group as authentic).
    #[test]
    fn first_contact_join_is_tofu_with_safety_number_required() {
        let alice = party("tofu", 41, "@alice");
        let mut bob = party("tofu", 42, "@bob");
        // Alice pins bob (to add him); bob pins NOBODY (first contact).
        let mut alice = alice;
        alice
            .pins
            .observe_verified("@bob", &bob.wire.verifying_key_bytes())
            .unwrap();

        let (mut group, _genesis) =
            create_group(&alice.provider, &alice.identity, "@research").unwrap();
        let kp = super::super::keypackages::build_one_time(&bob.provider, &bob.identity, 1)
            .unwrap()
            .remove(0);
        let outcome = add_member(
            &alice.provider,
            &alice.identity,
            &mut group,
            &kp.bytes,
            "@bob",
            &alice.pins,
            &mut alice.ledger,
        
            "@research",
            crate::mls::claim::CommitPromise::Inactive,
        )
        .unwrap();

        let joined = join_from_welcome(
            &bob.provider,
            &bob.identity,
            &outcome.welcome_bytes,
            "@research",
            &mut bob.pins,
            &mut bob.ledger,
            None,
        )
        .unwrap();
        assert_eq!(joined.trust, GenesisTrust::TofuRequiresSafetyNumber);
        assert!(
            joined.first_contact_handles.contains(&"@alice".to_string()),
            "alice was first contact for bob"
        );
        // Bob TOFU-pinned alice from the validated tree.
        assert!(bob.pins.pinned("@alice").is_some());

        let _ = fs::remove_dir_all(&alice.dir);
        let _ = fs::remove_dir_all(&bob.dir);
    }
}
