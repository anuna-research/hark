//! MLS-DS signature and hash domains owned by hark (SPEC-024 CON-002).
//!
//! Extracted from cbcl-rs's native proof at fd8f034. Only the tuple definitions
//! and strict signature profile are retained; the proof's recognizer, dialect
//! subset and stubbed request/response verification are not production code.
//! Parsing, role verification and canonical encoding remain generic cbcl-rs APIs.
//! Ed25519 operations use ed25519-dalek; no MLS cryptographic primitive is implemented here.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use cbcl_core::canonical::canonical_encode;
use cbcl_core::sexpr::{Atom, SExpr};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

/// The Ed25519 group order `L = 2^252 + 27742317777372353535851937790883648493`
/// in little-endian bytes (RFC 8032). A signature scalar `S` is canonical iff
/// `S ∈ [0, L)`.
const ED25519_L_LE: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// REQ-141 canonical-scalar predicate: `true` iff the little-endian 32-byte
/// scalar `s` satisfies `s ∈ [0, L)`. This is the exact `S += L` malleation
/// defence the threat-model "verifier-differential fork" row names — a
/// non-canonical `S` that a lax verifier would accept forks the DS log.
///
/// Enforced explicitly in-module so the REQ-141 stance does not silently
/// depend on an `ed25519-dalek` feature flag; the default `ed25519-dalek`
/// build *also* enforces it (`Scalar::from_canonical_bytes`), so this is
/// defence-in-depth that pins the semantics regardless of the dependency's
/// configuration.
pub fn scalar_is_canonical(s_le: &[u8; 32]) -> bool {
    // Compare little-endian from the most-significant byte down.
    for i in (0..32).rev() {
        if s_le[i] < ED25519_L_LE[i] {
            return true;
        }
        if s_le[i] > ED25519_L_LE[i] {
            return false;
        }
    }
    false // s == L is non-canonical (must be strictly < L)
}

/// Verify a 64-byte Ed25519 signature under the REQ-141 pinned strict profile:
///
/// 1. explicit canonical-`S` rejection (`S ∈ [0, L)`) — [`scalar_is_canonical`];
/// 2. `ed25519-dalek` v2 `verify_strict`, which
///    - rejects a public key `A` that fails to decompress;
///    - rejects small-order `R` and small-order `A`;
///    - compares `expected_R == signature.R` on the *compressed bytes*,
///      rejecting a non-canonically re-encoded `R`;
///    - uses the cofactorless equation `[S]B = R + [k]A` (RFC 8032 §5.1.7),
///      not the cofactored batch equation.
///
/// Any conformant verifier agrees with this on every 64-byte signature, so no
/// verifier-differential fork exists (state-invariant 53).
pub fn verify_strict_ed25519(vk_bytes: &[u8; 32], msg: &[u8], sig_bytes: &[u8; 64]) -> bool {
    let mut s_le = [0u8; 32];
    s_le.copy_from_slice(&sig_bytes[32..64]);
    if !scalar_is_canonical(&s_le) {
        return false; // REQ-141: reject non-canonical S (the S += L malleation)
    }
    let Ok(vk) = VerifyingKey::from_bytes(vk_bytes) else {
        return false; // non-decodable / non-canonical public-key point encoding
    };
    let sig = Signature::from_bytes(sig_bytes);
    vk.verify_strict(msg, &sig).is_ok()
}

/// An Ed25519 signer for MLS-DS interoperability fixtures (deterministic from a 32-byte seed —
/// no RNG, so vectors are reproducible). Real curve arithmetic, real signing.
pub struct Ed25519Keypair {
    signing: SigningKey,
}

impl Ed25519Keypair {
    /// Deterministic keypair from a 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(seed),
        }
    }

    /// The 32-byte Ed25519 public key.
    pub fn public_bytes(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// The `mls-ds/v1` key-id spelling: `@` + 43-char canonical base64url.
    pub fn key_id(&self) -> String {
        let mut s = String::from("@");
        s.push_str(&b64url_encode(&self.public_bytes()));
        s
    }

    /// Sign `msg` with real Ed25519 (RFC 8032), returning the 64-byte signature.
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing.sign(msg).to_bytes()
    }
}

/// Canonical, unpadded base64url used for MLS-DS keys and signatures.
pub fn b64url_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The domain-tagged tuple as an S-expression: `(domain_tag field₀ field₁ …)`.
pub fn tuple_sexpr(domain_tag: &str, fields: &[SExpr]) -> SExpr {
    let mut items = Vec::with_capacity(1 + fields.len());
    items.push(SExpr::Atom(Atom::Symbol(String::from(domain_tag))));
    items.extend_from_slice(fields);
    SExpr::List(items)
}

/// CON-002 "Canonical signable bytes (single definition)": the RFC 9804
/// `canonical_encode` of the domain-tagged tuple. This is the sole
/// signed/hashed preimage for every CON-002 domain tuple.
pub fn canonical_signable_bytes(domain_tag: &str, fields: &[SExpr]) -> Vec<u8> {
    canonical_encode(&tuple_sexpr(domain_tag, fields))
}

/// `sign_tuple(domain_tag, fields) -> sig`: real Ed25519 over the canonical
/// signable bytes.
pub fn sign_tuple(kp: &Ed25519Keypair, domain_tag: &str, fields: &[SExpr]) -> [u8; 64] {
    kp.sign(&canonical_signable_bytes(domain_tag, fields))
}

/// `verify_tuple(...) -> bool`: strict-profile (REQ-141) verify over the
/// canonical signable bytes.
pub fn verify_tuple(vk: &[u8; 32], domain_tag: &str, fields: &[SExpr], sig: &[u8; 64]) -> bool {
    verify_strict_ed25519(vk, &canonical_signable_bytes(domain_tag, fields), sig)
}

/// `SHA-256(canonical_encode(("<tag>", …)))` rendered `sha256:<hex64>` — the
/// content-hash construction used by `record_hash`, `anchor_hash`,
/// `offer_hash`, and every `*-hash-v1` tuple (distinct from `h0`/`h1`, which
/// use the typed Merkle root).
pub fn tuple_content_hash(domain_tag: &str, fields: &[SExpr]) -> String {
    sha256_hex(&canonical_signable_bytes(domain_tag, fields))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::from("sha256:");
    push_hex(&mut out, &digest);
    out
}

fn push_hex(out: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
}

// ---------------------------------------------------------------------------
// The ~16 CON-002 signature/hash domain tuples, as typed structures.
// ---------------------------------------------------------------------------

/// Every CON-002 signature-tuple domain, with its exact domain tag. The field
/// list of each is built from typed inputs (helpers below), so the "canonical
/// signable bytes" of each is fixed by construction and domain-separated by the
/// leading tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainTuple {
    /// `("mls-ds-open-signature-v1", bindings, dialect_hash, opener-message)`
    Open {
        bindings: SExpr,
        dialect_hash: String,
        opener_message: SExpr,
    },
    /// `("mls-ds-request-signature-v1", bindings, dialect_hash, h0, request,
    ///   read-context-or-none)`
    Request {
        bindings: SExpr,
        dialect_hash: String,
        h0: String,
        request: SExpr,
        read_context: ReadContext,
    },
    /// `("mls-ds-response-signature-v1", bindings, dialect_hash,
    ///   request-content-hash, response-message, read-context-or-none)`
    Response {
        bindings: SExpr,
        dialect_hash: String,
        request_content_hash: String,
        response_message: SExpr,
        read_context: ReadContext,
    },
    /// `("mls-ds-source-signature-v1", source)`
    Source { source: SExpr },
    /// `("mls-add-authorization-v1", room, source-author-key, base-seq,
    ///   base-hash, ciphertext-digest, targets, welcome-digest,
    ///   genesis-anchor-hash)`
    AddAuth {
        room: String,
        source_author_key: String,
        base_seq: i64,
        base_hash: String,
        ciphertext_digest: String,
        targets: Vec<String>,
        welcome_digest: String,
        genesis_anchor_hash: String,
    },
    /// `("mls-ds-record-signature-v1", log-record)`
    Record { log_record: SExpr },
    /// `("mls-room-claim-signature-v1", room-claim-core)`
    Claim { room_claim_core: SExpr },
    /// `("mls-room-claim-ds-signature-v1", room-claim-core, creator-signature)`
    ClaimDs {
        room_claim_core: SExpr,
        creator_signature: String,
    },
    /// `("mls-genesis-signature-v1", room, genesis-blob-ref, creator-key)`
    Genesis {
        room: String,
        genesis_blob_ref: SExpr,
        creator_key: String,
    },
    /// `("mls-ds-successor-predecessor-offer-signature-v1", successor-offer-core)`
    PredecessorOffer { successor_offer_core: SExpr },
    /// `("mls-ds-successor-successor-consent-signature-v1", successor-offer)`
    SuccessorConsent { successor_offer: SExpr },
    /// `("mls-ds-successor-ds-signature-v1", successor-proposal)`
    SuccessorDs { successor_proposal: SExpr },
    /// `("mls-ds-successor-offer-hash-v1", successor-offer)` (hashed, not signed)
    OfferHash { successor_offer: SExpr },
    /// `("mls-ds-successor-hash-v1", successor-value)` (the bridge hash)
    BridgeHash { successor_value: SExpr },
    /// `("mls-ds-closure-package-hash-v1", closure-package)` (hashed)
    ClosurePackageHash { closure_package: SExpr },
}

/// A read request's authenticated session/frame replay tuple, or `none` for a
/// mutation. `("mls-ds-read-context-v1", session-id, frame-id)` when present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadContext {
    /// Mutation roots cover the CBCL atom `none`.
    None,
    /// Read roots cover `(session-id, frame-id)`.
    Read { session_id: String, frame_id: i64 },
}

impl ReadContext {
    fn to_sexpr(&self) -> SExpr {
        match self {
            ReadContext::None => SExpr::Atom(Atom::Symbol(String::from("none"))),
            ReadContext::Read {
                session_id,
                frame_id,
            } => tuple_sexpr(
                "mls-ds-read-context-v1",
                &[
                    SExpr::Atom(Atom::Str(session_id.clone())),
                    SExpr::Atom(Atom::Num(*frame_id)),
                ],
            ),
        }
    }
}

fn qhash(h: &str) -> SExpr {
    SExpr::Atom(Atom::Str(String::from(h)))
}
fn qstr(s: &str) -> SExpr {
    SExpr::Atom(Atom::Str(String::from(s)))
}
fn sym(s: &str) -> SExpr {
    SExpr::Atom(Atom::Symbol(String::from(s)))
}
fn num(n: i64) -> SExpr {
    SExpr::Atom(Atom::Num(n))
}

impl DomainTuple {
    /// The exact CON-002 domain tag.
    pub fn domain_tag(&self) -> &'static str {
        match self {
            DomainTuple::Open { .. } => "mls-ds-open-signature-v1",
            DomainTuple::Request { .. } => "mls-ds-request-signature-v1",
            DomainTuple::Response { .. } => "mls-ds-response-signature-v1",
            DomainTuple::Source { .. } => "mls-ds-source-signature-v1",
            DomainTuple::AddAuth { .. } => "mls-add-authorization-v1",
            DomainTuple::Record { .. } => "mls-ds-record-signature-v1",
            DomainTuple::Claim { .. } => "mls-room-claim-signature-v1",
            DomainTuple::ClaimDs { .. } => "mls-room-claim-ds-signature-v1",
            DomainTuple::Genesis { .. } => "mls-genesis-signature-v1",
            DomainTuple::PredecessorOffer { .. } => {
                "mls-ds-successor-predecessor-offer-signature-v1"
            }
            DomainTuple::SuccessorConsent { .. } => {
                "mls-ds-successor-successor-consent-signature-v1"
            }
            DomainTuple::SuccessorDs { .. } => "mls-ds-successor-ds-signature-v1",
            DomainTuple::OfferHash { .. } => "mls-ds-successor-offer-hash-v1",
            DomainTuple::BridgeHash { .. } => "mls-ds-successor-hash-v1",
            DomainTuple::ClosurePackageHash { .. } => "mls-ds-closure-package-hash-v1",
        }
    }

    /// The tuple's ordered fields (after the domain tag).
    pub fn fields(&self) -> Vec<SExpr> {
        match self {
            DomainTuple::Open {
                bindings,
                dialect_hash,
                opener_message,
            } => vec![
                bindings.clone(),
                qhash(dialect_hash),
                opener_message.clone(),
            ],
            DomainTuple::Request {
                bindings,
                dialect_hash,
                h0,
                request,
                read_context,
            } => vec![
                bindings.clone(),
                qhash(dialect_hash),
                qhash(h0),
                request.clone(),
                read_context.to_sexpr(),
            ],
            DomainTuple::Response {
                bindings,
                dialect_hash,
                request_content_hash,
                response_message,
                read_context,
            } => vec![
                bindings.clone(),
                qhash(dialect_hash),
                qhash(request_content_hash),
                response_message.clone(),
                read_context.to_sexpr(),
            ],
            DomainTuple::Source { source } => vec![source.clone()],
            DomainTuple::AddAuth {
                room,
                source_author_key,
                base_seq,
                base_hash,
                ciphertext_digest,
                targets,
                welcome_digest,
                genesis_anchor_hash,
            } => vec![
                qstr(room),
                sym(source_author_key),
                num(*base_seq),
                qhash(base_hash),
                qhash(ciphertext_digest),
                SExpr::List(targets.iter().map(|k| sym(k)).collect()),
                qhash(welcome_digest),
                qhash(genesis_anchor_hash),
            ],
            DomainTuple::Record { log_record } => vec![log_record.clone()],
            DomainTuple::Claim { room_claim_core } => vec![room_claim_core.clone()],
            DomainTuple::ClaimDs {
                room_claim_core,
                creator_signature,
            } => vec![room_claim_core.clone(), qstr(creator_signature)],
            DomainTuple::Genesis {
                room,
                genesis_blob_ref,
                creator_key,
            } => vec![qstr(room), genesis_blob_ref.clone(), sym(creator_key)],
            DomainTuple::PredecessorOffer {
                successor_offer_core,
            } => vec![successor_offer_core.clone()],
            DomainTuple::SuccessorConsent { successor_offer } => vec![successor_offer.clone()],
            DomainTuple::SuccessorDs { successor_proposal } => vec![successor_proposal.clone()],
            DomainTuple::OfferHash { successor_offer } => vec![successor_offer.clone()],
            DomainTuple::BridgeHash { successor_value } => vec![successor_value.clone()],
            DomainTuple::ClosurePackageHash { closure_package } => vec![closure_package.clone()],
        }
    }

    /// Canonical signable bytes of this tuple.
    pub fn signable_bytes(&self) -> Vec<u8> {
        canonical_signable_bytes(self.domain_tag(), &self.fields())
    }

    /// Sign with real Ed25519 under the strict profile.
    pub fn sign(&self, kp: &Ed25519Keypair) -> [u8; 64] {
        kp.sign(&self.signable_bytes())
    }

    /// Verify under the REQ-141 strict profile.
    pub fn verify(&self, vk: &[u8; 32], sig: &[u8; 64]) -> bool {
        verify_strict_ed25519(vk, &self.signable_bytes(), sig)
    }

    /// `sha256:<hex64>` content hash (for the hash-tuple domains).
    pub fn content_hash(&self) -> String {
        sha256_hex(&self.signable_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn kp(n: u8) -> Ed25519Keypair {
        Ed25519Keypair::from_seed(&[n; 32])
    }
    /// The little-endian order L (re-derived locally so the vector does not lean on
    /// a module-private constant).
    const L_LE: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];

    fn add_l(s: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut carry = 0u16;
        for i in 0..32 {
            let sum = s[i] as u16 + L_LE[i] as u16 + carry;
            out[i] = (sum & 0xff) as u8;
            carry = sum >> 8;
        }
        assert_eq!(carry, 0, "s + L must fit in 256 bits");
        out
    }

    #[test]
    fn t18_13_canonical_signature_accepted() {
        let a = kp(9);
        let msg = b"mls-ds/v1 canonical vector";
        let sig = a.sign(msg);
        assert!(verify_strict_ed25519(&a.public_bytes(), msg, &sig));
    }

    #[test]
    fn t18_13_s_plus_l_malleation_rejected() {
        // The headline REQ-141 defence: S += L verifies under a lax verifier but is
        // rejected by the canonical-S check, so no verifier-differential fork.
        let a = kp(9);
        let msg = b"mls-ds/v1 canonical vector";
        let sig = a.sign(msg);
        let mut s = [0u8; 32];
        s.copy_from_slice(&sig[32..64]);
        assert!(scalar_is_canonical(&s), "the honest S is canonical");
        let s_prime = add_l(&s);
        assert!(!scalar_is_canonical(&s_prime), "S + L is non-canonical");
        // The concrete verifier-differential: S + L still passes the *lax*
        // top-3-bits check (`s[31] & 0xE0 == 0`) that a non-strict verifier uses,
        // so a lax verifier would ACCEPT this malleation while the strict profile
        // rejects it — exactly the fork the threat model names.
        assert_eq!(
            s_prime[31] & 0xE0,
            0,
            "S + L passes the lax top-3-bits check (would fork a non-strict verifier)"
        );
        let mut malleated = sig;
        malleated[32..64].copy_from_slice(&s_prime);
        assert!(
            !verify_strict_ed25519(&a.public_bytes(), msg, &malleated),
            "S += L must be rejected"
        );
    }

    #[test]
    fn t18_13_low_order_r_rejected() {
        // R replaced by the identity-point encoding (order 1, small order).
        let a = kp(9);
        let msg = b"mls-ds/v1 canonical vector";
        let sig = a.sign(msg);
        let mut bad = sig;
        let mut identity = [0u8; 32];
        identity[0] = 1; // canonical encoding of the identity point
        bad[0..32].copy_from_slice(&identity);
        assert!(!verify_strict_ed25519(&a.public_bytes(), msg, &bad));
    }

    #[test]
    fn t18_13_noncanonical_point_encoding_rejected() {
        // R presented as a non-canonical / mismatched field encoding (top bits set,
        // y ≥ p): verify_strict recomputes the canonical R and the byte comparison
        // (or decode failure) rejects it.
        let a = kp(9);
        let msg = b"mls-ds/v1 canonical vector";
        let sig = a.sign(msg);
        let mut bad = sig;
        bad[0..32].copy_from_slice(&[0xff; 32]);
        assert!(!verify_strict_ed25519(&a.public_bytes(), msg, &bad));
    }

    #[test]
    fn t18_13_small_order_public_key_rejected() {
        // A weak (small-order) public key A is rejected by verify_strict.
        let a = kp(9);
        let msg = b"mls-ds/v1 canonical vector";
        let sig = a.sign(msg);
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert!(!verify_strict_ed25519(&identity, msg, &sig));
    }
}
