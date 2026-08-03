//! MLS private channels (SPEC-013 / IMPL-013).
//!
//! hark's side of the encrypted-private-channel capability: OpenMLS pinned to
//! the exact stack the web client's `cbcl-mls-wasm` builds against (ADR-003),
//! with the MLS leaf credential signed by the agent's wire Ed25519 identity
//! key (REQ-007, ADR-002) so MLS membership is anchored to the authenticated
//! wire identity rather than a fresh keypair bound only by handle string.
//!
//! Submodules follow the IMPL-013 plan:
//! - [`provider`] — durable OpenMLS storage under `identity_dir` (ADR-004).
//! - [`pins`] — handle→wire-key pinning + the domain-separated `idkey` /
//!   `rekey` assertion contexts (REQ-011, REQ-019).
//! - [`keypackages`] — KeyPackage build/publish/consume with the single-use
//!   ledger (REQ-002, REQ-013, REQ-022).
//! - [`group`] — group creation (genesis extension, K-2 guard), owner
//!   election over MLS leaves, Welcome validation (REQ-001/003/004/008/012/016).
//! - [`validation`] — inbound membership-change validation, sender-auth,
//!   encrypt/decrypt (REQ-005/006/017/018).
//! - [`removal`] — signed removal evidence (REQ-014).
//! - [`safety`] — identity safety number + epoch state hash (REQ-021/024).
//! - [`session`] — encryption-mode pin + the chat-session facade (REQ-023).

pub mod claim;
pub mod epochop;
pub mod group;
pub mod keypackages;
pub mod pins;
pub mod provider;
pub mod removal;
pub mod safety;
pub mod session;
pub mod validation;

use openmls::prelude::Ciphersuite;
use openmls::prelude::{BasicCredential, CredentialWithKey};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::types::SignatureScheme;

use crate::identity::ChatIdentity;

/// The one ciphersuite both stacks pin (NFR-001); its signature scheme is
/// Ed25519, which is what lets the wire identity key double as the leaf
/// signature key (ADR-002).
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// GroupContext application extension carrying the creator-signed genesis
/// assertion (REQ-016). Every leaf must advertise this type in its
/// capabilities; openmls enforces it fail-closed at Add/Welcome time.
pub const GENESIS_EXT_TYPE: u16 = 0xF013;

/// Domain-separation labels for every app-signed context (OQ-001): each is
/// disjoint from the wire envelope's `cbcl-signed-member/v1` and from MLS
/// `SignWithLabel`, so no signature can be transplanted across contexts.
pub const DS_IDKEY_ASSERT: &str = "cbcl-idkey-assert/v1";
/// Cross-signed key-rotation ceremony label (REQ-011).
pub const DS_IDKEY_ROTATE: &str = "cbcl-idkey-rotate/v1";
/// Removal-evidence label (REQ-014).
pub const DS_MLS_REMOVE: &str = "cbcl-mls-remove/v1";
/// Creator-signed group-genesis assertion label (REQ-016).
pub const DS_MLS_GENESIS: &str = "cbcl-mls-genesis/v1";
/// Fork-recovery resync-request label (REQ-025). Signed by the requesting
/// member's own wire key so the untrusted hub cannot forge a `:resync` that
/// would drive a REQ-014 Remove (the F1 eviction vector). Same field layout as
/// [`DS_IDKEY_ASSERT`] under a distinct label; MUST equal cbcl-bus's
/// `DS_MLS_RESYNC` (crates/cbcl-mls-wasm) for NFR-001 byte parity.
pub const DS_MLS_RESYNC: &str = "cbcl-mls-resync/v1";
/// Identity-safety-number frame label (REQ-021).
pub const DS_IDENTITY_SAFETY: &str = "cbcl-mls-identity-safety/v1";
/// Creator-signed admission-grant label (SPEC-061 REQ-002). MUST equal
/// cbcl-bus's `DS_MLS_INVITE` (crates/cbcl-mls-wasm) — it is part of the signed
/// bytes, so a mismatch makes an invite minted on one stack unredeemable on the
/// other, which is a channel partitioned between agent and web members.
///
/// The grant is what lets a channel's creator authorise an admission ONCE, in
/// advance, instead of having to be online when somebody redeems it. It is the
/// precondition for accepting RFC 9420 §12.4.3.2 external Commits at all: a
/// joiner needs a GroupInfo, GroupInfo distribution is an application choice, and
/// the distributor is a hub the RFC assumes is "largely untrusted" (§3). Were
/// possession of a GroupInfo sufficient, group admission would pass to whoever
/// hands them out. §12.3 permits the rule that closes this — "An application may
/// extend the above procedure by additional rules, for example, requiring
/// application-level permissions to add members".
pub const DS_MLS_INVITE: &str = "cbcl-mls-invite/v1";

/// Pairing admission-grant label (SPEC-061 REQ-008). MUST equal cbcl-bus's
/// `DS_MLS_PAIRGRANT`.
///
/// The credential by which the member that PAIRED an agent authorises it to seat
/// itself — the case [`DS_MLS_INVITE`] cannot serve, because an invited member may
/// pair an agent and may not commit an Add for it, so it hands out a pairing it
/// has no way to complete.
///
/// A separate credential rather than a second use of the invite grant, for a
/// reason that is about carriage. An invite grant is bearer, and survives being
/// carried by an untrusted hub only because it is sealed under a key that rides in
/// the invite link. A pairing code cannot key such a seal: the hub mints the code
/// and runs the SPAKE2 responder, so it holds password-equivalent material
/// (SPEC-061 REQ-007 rules the idea out on exactly these grounds). So this grant is
/// not secret — it is BOUND. Its signed context names the subject's handle and the
/// subject's wire key, and every verifier requires the external Commit's path leaf
/// to be that exact pair, which makes reading it worth nothing to a reader that
/// does not hold the key.
pub const DS_MLS_PAIRGRANT: &str = "cbcl-mls-pairgrant/v1";

/// Leaf capabilities advertising the genesis extension type. REQ-016 obliges
/// every hark and web-client KeyPackage/leaf to carry this; openmls then
/// rejects (fail-closed) any member that cannot process the genesis
/// extension (`InsufficientCapabilities`, observed by the §10 spike).
pub fn genesis_capabilities() -> openmls::prelude::Capabilities {
    openmls::prelude::Capabilities::new(
        None,
        None,
        Some(&[openmls::prelude::ExtensionType::Unknown(GENESIS_EXT_TYPE)]),
        None,
        None,
    )
}

/// Errors from the MLS subsystem. Validation rejections are deliberately
/// distinct from transport/storage faults: a rejection is a *security
/// decision* (fail closed), not an I/O problem.
#[derive(Debug, thiserror::Error)]
pub enum MlsError {
    /// A frame, KeyPackage, Welcome, Commit, or proposal failed SPEC-013
    /// validation and was rejected. The string names the violated predicate.
    #[error("rejected: {0}")]
    Rejected(String),
    /// A transient precondition is not yet met — most notably, this agent is
    /// not yet a member of the room's MLS group because no Welcome has
    /// arrived. Unlike [`MlsError::Rejected`], this is NOT a security
    /// decision (fail closed): the *same* operation succeeds once the session
    /// catches up, so callers must treat it as retryable rather than
    /// health-fatal. Failing closed (no plaintext fallback) still holds.
    #[error("not ready: {0}")]
    NotReady(String),
    /// The underlying OpenMLS stack failed.
    #[error("mls stack: {0}")]
    Stack(String),
    /// Durable state could not be read/written.
    #[error("mls storage: {0}")]
    Storage(#[from] std::io::Error),
}

impl MlsError {
    pub(crate) fn stack<E: std::fmt::Debug>(context: &str) -> impl FnOnce(E) -> MlsError + '_ {
        move |e| MlsError::Stack(format!("{context}: {e:?}"))
    }
}

/// The agent's MLS identity: the wire Ed25519 key as leaf signer (REQ-007)
/// plus the BasicCredential carrying the canonical handle (with `@`).
pub struct MlsIdentity {
    pub signer: SignatureKeyPair,
    pub credential: CredentialWithKey,
    pub handle: String,
}

impl MlsIdentity {
    /// Bind the MLS leaf to the wire identity: the leaf signature key IS the
    /// wire Ed25519 key — not a freshly generated one (REQ-007, ADR-002).
    pub fn from_wire_identity(identity: &ChatIdentity, handle: &str) -> Self {
        let signer = SignatureKeyPair::from_raw(
            SignatureScheme::ED25519,
            identity.signing_seed().to_vec(),
            identity.verifying_key_bytes().to_vec(),
        );
        let credential = CredentialWithKey {
            credential: BasicCredential::new(handle.as_bytes().to_vec()).into(),
            signature_key: signer.public().into(),
        };
        Self {
            signer,
            credential,
            handle: handle.to_string(),
        }
    }

    /// The raw 32-byte Ed25519 leaf/wire public key.
    pub fn public_key(&self) -> &[u8] {
        self.signer.public()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TEST-007 (REQ-007): the MLS leaf credential signature key equals the
    /// wire identity's Ed25519 public key — byte for byte.
    #[test]
    fn leaf_signature_key_is_the_wire_identity_key() {
        let wire = ChatIdentity::from_seed([42u8; 32]);
        let mls = MlsIdentity::from_wire_identity(&wire, "@aria");
        assert_eq!(mls.public_key(), wire.verifying_key_bytes().as_slice());
        assert_eq!(
            mls.credential.signature_key.as_slice(),
            wire.verifying_key_bytes().as_slice()
        );
    }

    /// The credential identity is the canonical handle bytes (with `@`).
    #[test]
    fn credential_identity_is_the_handle() {
        let wire = ChatIdentity::from_seed([7u8; 32]);
        let mls = MlsIdentity::from_wire_identity(&wire, "@aria");
        let basic = BasicCredential::try_from(mls.credential.credential.clone()).expect("basic");
        assert_eq!(basic.identity(), b"@aria");
    }

    /// The bound signer produces signatures the wire verifying key accepts —
    /// same primitive, same key, two domains (OQ-001 keeps them disjoint).
    #[test]
    fn bound_signer_signs_under_the_wire_key() {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        use openmls_traits::signatures::Signer as _;
        let wire = ChatIdentity::from_seed([9u8; 32]);
        let mls = MlsIdentity::from_wire_identity(&wire, "@aria");
        let sig = mls.signer.sign(b"payload").expect("sign");
        let vk = VerifyingKey::from_bytes(&wire.verifying_key_bytes()).expect("vk");
        let sig = Signature::from_slice(&sig).expect("sig");
        assert!(vk.verify(b"payload", &sig).is_ok());
    }
}
