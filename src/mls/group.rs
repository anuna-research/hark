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
    ledger: &ConsumedLedger,
    room: &str,
    promise: super::claim::CommitPromise<'_>,
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
    check_promise(&promise, room, group.epoch().as_u64())?;

    let (commit, welcome, _group_info) = group
        .add_members(provider, &identity.signer, &[kp])
        .map_err(MlsError::stack("add members"))?;
    group
        .merge_pending_commit(provider)
        .map_err(MlsError::stack("merge own add commit"))?;
    provider.persist()?;
    Ok(AddOutcome {
        commit_bytes: commit
            .tls_serialize_detached()
            .map_err(MlsError::stack("serialize commit"))?,
        welcome_bytes: welcome
            .tls_serialize_detached()
            .map_err(MlsError::stack("serialize welcome"))?,
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
        // mark_consumed errors only on duplicates, which we pre-checked.
        let _ = ledger.mark_consumed(ref_b64);
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
            &alice.ledger,
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
            &alice.ledger,
        
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
            &alice.ledger,
        
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
                &alice.ledger,
            
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
                &alice.ledger,
            
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
            &mallory.ledger,
        
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
            &alice.ledger,
        
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
            &alice.ledger,
        
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
            &alice.ledger,
        
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
