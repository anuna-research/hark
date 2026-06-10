//! SPEC-013 §10 spike — helpers that mirror `cbcl-mls-wasm`'s Provider/Identity/
//! Group operations against native OpenMLS 0.8, plus the probe hooks the wasm
//! binding does not expose (custom KeyPackage lifetime, credential-changing
//! self-update). Faithful to `cbcl-chat/crates/cbcl-mls-wasm/src/lib.rs` so the
//! observed behaviour is the web artifact's behaviour at the pinned version.
//!
//! This is a TEST ORACLE, not the gated design. No wire framing, no signed-member
//! envelope, no app-level pin checks — those are SPEC-013's job. Here we only
//! characterise what OpenMLS itself does, so the human signer is not taking the
//! round-3 review's OpenMLS assumptions on faith.

use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

/// The ciphersuite pinned by NFR-001 (must match cbcl-mls-wasm exactly).
pub const CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// A single member: an OpenMLS provider (RustCrypto + in-memory storage), a
/// signature keypair, and a BasicCredential over a handle string. Mirrors
/// `Provider` + `Identity` in the wasm binding.
pub struct Party {
    pub provider: OpenMlsRustCrypto,
    pub signer: SignatureKeyPair,
    pub credential: CredentialWithKey,
    pub handle: String,
}

impl Party {
    /// Create a member bound to `handle`, mirroring `Identity::new`.
    pub fn new(handle: &str) -> Self {
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
            .expect("signature keypair");
        signer.store(provider.storage()).expect("store signer");
        let credential = CredentialWithKey {
            credential: BasicCredential::new(handle.as_bytes().to_vec()).into(),
            signature_key: signer.public().into(),
        };
        Party { provider, signer, credential, handle: handle.to_string() }
    }

    /// A fresh KeyPackage (default lifetime), TLS-serialized — mirrors
    /// `Identity::key_package`.
    pub fn key_package(&self) -> Vec<u8> {
        self.build_key_package(KeyPackage::builder())
    }

    /// A KeyPackage with a caller-supplied builder, so a probe can set a custom
    /// `lifetime`. Returns the TLS-serialized KeyPackage bytes.
    pub fn build_key_package(&self, builder: KeyPackageBuilder) -> Vec<u8> {
        builder
            .build(CIPHERSUITE, &self.provider, &self.signer, self.credential.clone())
            .expect("build key package")
            .key_package()
            .tls_serialize_detached()
            .expect("serialize key package")
    }

    /// Create a brand-new group owned by this member. Ratchet-tree extension on,
    /// matching the wasm binding (self-contained Welcomes).
    pub fn create_group(&self) -> MlsGroup {
        let cfg = MlsGroupCreateConfig::builder()
            .use_ratchet_tree_extension(true)
            .ciphersuite(CIPHERSUITE)
            .build();
        MlsGroup::new(&self.provider, &self.signer, &cfg, self.credential.clone())
            .expect("create group")
    }
}

/// Validate + deserialize a published KeyPackage (the adder's view). Returns the
/// error string on rejection so a probe can assert *why* (e.g. expired lifetime).
pub fn validate_key_package(
    adder: &Party,
    key_package_bytes: &[u8],
) -> Result<KeyPackage, String> {
    let kp_in = KeyPackageIn::tls_deserialize_exact(key_package_bytes)
        .map_err(|e| format!("deserialize: {e:?}"))?;
    kp_in
        .validate(adder.provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|e| format!("validate: {e:?}"))
}

/// Add a validated member; returns (commit_bytes, welcome_bytes), mirroring
/// `Group::add_member`. Merges the adder's pending commit.
pub fn add_member(
    group: &mut MlsGroup,
    adder: &Party,
    key_package_bytes: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let kp = validate_key_package(adder, key_package_bytes)?;
    let (commit, welcome, _gi) = group
        .add_members(&adder.provider, &adder.signer, &[kp])
        .map_err(|e| format!("add_members: {e:?}"))?;
    group
        .merge_pending_commit(&adder.provider)
        .map_err(|e| format!("merge: {e:?}"))?;
    Ok((
        commit.tls_serialize_detached().map_err(|e| format!("ser commit: {e:?}"))?,
        welcome.tls_serialize_detached().map_err(|e| format!("ser welcome: {e:?}"))?,
    ))
}

/// Join a group from Welcome bytes — mirrors `Group::join`.
pub fn join(joiner: &Party, welcome_bytes: &[u8]) -> Result<MlsGroup, String> {
    let msg = MlsMessageIn::tls_deserialize_exact(welcome_bytes)
        .map_err(|e| format!("deserialize welcome: {e:?}"))?;
    let welcome = match msg.extract() {
        MlsMessageBodyIn::Welcome(w) => w,
        _ => return Err("expected a Welcome".into()),
    };
    let cfg = MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();
    StagedWelcome::new_from_welcome(&joiner.provider, &cfg, welcome, None)
        .map_err(|e| format!("staged welcome: {e:?}"))?
        .into_group(&joiner.provider)
        .map_err(|e| format!("into group: {e:?}"))
}

/// Like [`join`] but with an explicit `max_past_epochs` retention window on the
/// joiner's group. Retention is a property of the **decrypting** group instance
/// (set via its JoinConfig), so a probe testing the NFR-004/OQ-005 window must set
/// it here, not only on the creator's config.
pub fn join_with_past_epochs(
    joiner: &Party,
    welcome_bytes: &[u8],
    max_past_epochs: usize,
) -> Result<MlsGroup, String> {
    let msg = MlsMessageIn::tls_deserialize_exact(welcome_bytes)
        .map_err(|e| format!("deserialize welcome: {e:?}"))?;
    let welcome = match msg.extract() {
        MlsMessageBodyIn::Welcome(w) => w,
        _ => return Err("expected a Welcome".into()),
    };
    let cfg = MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .max_past_epochs(max_past_epochs)
        .build();
    StagedWelcome::new_from_welcome(&joiner.provider, &cfg, welcome, None)
        .map_err(|e| format!("staged welcome: {e:?}"))?
        .into_group(&joiner.provider)
        .map_err(|e| format!("into group: {e:?}"))
}

/// Encrypt an application message — mirrors `Group::encrypt`.
pub fn encrypt(group: &mut MlsGroup, sender: &Party, plaintext: &[u8]) -> Vec<u8> {
    group
        .create_message(&sender.provider, &sender.signer, plaintext)
        .expect("create message")
        .tls_serialize_detached()
        .expect("serialize message")
}

/// The result of processing one inbound MLS message.
pub enum Processed {
    /// An application message: (plaintext, authenticated sender leaf index).
    App(Vec<u8>, LeafNodeIndex),
    /// A handshake message that was merged/stored.
    Handshake,
}

/// Process an inbound message, merging commits and exposing the **authenticated
/// sender leaf index** for application messages (this is what REQ-018 needs to
/// resolve `:from`). Mirrors `Group::process` but returns the sender so probes
/// can inspect the leaf credential the sender actually carries.
pub fn process(
    group: &mut MlsGroup,
    receiver: &Party,
    wire: &[u8],
) -> Result<Processed, String> {
    let msg = MlsMessageIn::tls_deserialize_exact(wire)
        .map_err(|e| format!("deserialize: {e:?}"))?;
    let protocol = msg
        .try_into_protocol_message()
        .map_err(|e| format!("protocol message: {e:?}"))?;
    let processed = group
        .process_message(&receiver.provider, protocol)
        .map_err(|e| format!("process_message: {e:?}"))?;
    let sender = processed.sender().clone();
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(app) => {
            let leaf = match sender {
                Sender::Member(idx) => idx,
                other => return Err(format!("app message from non-member sender: {other:?}")),
            };
            Ok(Processed::App(app.into_bytes(), leaf))
        }
        ProcessedMessageContent::StagedCommitMessage(staged) => {
            group
                .merge_staged_commit(&receiver.provider, *staged)
                .map_err(|e| format!("merge staged: {e:?}"))?;
            Ok(Processed::Handshake)
        }
        ProcessedMessageContent::ProposalMessage(p) => {
            group
                .store_pending_proposal(receiver.provider.storage(), *p)
                .map_err(|e| format!("store proposal: {e:?}"))?;
            Ok(Processed::Handshake)
        }
        ProcessedMessageContent::ExternalJoinProposalMessage(p) => {
            group
                .store_pending_proposal(receiver.provider.storage(), *p)
                .map_err(|e| format!("store ext proposal: {e:?}"))?;
            Ok(Processed::Handshake)
        }
    }
}

/// The BasicCredential identity bytes of the leaf at `index`, if any — used to
/// read what handle a member's leaf currently *claims* (the R3-07 question).
pub fn leaf_identity(group: &MlsGroup, index: LeafNodeIndex) -> Option<Vec<u8>> {
    group.members().find(|m| m.index == index).and_then(|m| {
        BasicCredential::try_from(m.credential.clone()).ok().map(|bc| bc.identity().to_vec())
    })
}
