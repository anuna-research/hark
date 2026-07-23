//! TEST-024 oracle 2 (crypto admission) — the COMPLETE corrected-tuple sweep.
//!
//! [[IMPL-025-hark-mls-ds-client#TEST-024]] oracle 2 / [[IMPL-025-hark-mls-ds-client#ADR-032]]
//! require the crypto-admission proof over the **complete** `DomainTuple` inventory — not just
//! `AddAuth`. This asserts the full **domain-separation matrix**: all 15 corrected CON-002
//! tuples have distinct tags, each signature verifies under its OWN tag, and NO signature
//! verifies under ANY of the other 14 tags (210 domain-transplant rejections). Plus a
//! per-tuple field-mutation rejection.
//!
//! Crypto CONSUMED from `cbcl-core::mls_ds` (native, the DS-branch proof artifact — same code
//! proven native↔NIF↔wasm32 by `df90533`). Pre-pin.
//!
//!   cargo test --manifest-path experiments/spec-024-mls-ds-canonical-spike/Cargo.toml \
//!       --test test024_crypto_admission_full -- --nocapture

use cbcl_core::mls_ds::{verify_tuple, DomainTuple, Ed25519Keypair, ReadContext};
use cbcl_core::sexpr::{Atom, SExpr};

fn sx(s: &str) -> SExpr {
    SExpr::Atom(Atom::Str(s.into()))
}
fn digest(nib: &str) -> String {
    format!("sha256:{}", nib.repeat(64))
}

/// One representative valid instance of every one of the 15 `DomainTuple` variants.
fn all_15() -> Vec<(&'static str, DomainTuple)> {
    vec![
        ("Open", DomainTuple::Open { bindings: sx("b"), dialect_hash: digest("1"), opener_message: sx("m") }),
        ("Request", DomainTuple::Request { bindings: sx("b"), dialect_hash: digest("1"), h0: digest("0"), request: sx("r"), read_context: ReadContext::Read { session_id: "s".into(), frame_id: 1 } }),
        ("Response", DomainTuple::Response { bindings: sx("b"), dialect_hash: digest("1"), request_content_hash: digest("2"), response_message: sx("m"), read_context: ReadContext::None }),
        ("Source", DomainTuple::Source { source: sx("s") }),
        ("AddAuth", DomainTuple::AddAuth { room: "room-alpha".into(), source_author_key: "@k".into(), base_seq: 1, base_hash: digest("a"), ciphertext_digest: digest("b"), targets: vec!["@alice".into()], welcome_digest: digest("c"), genesis_anchor_hash: digest("d") }),
        ("Record", DomainTuple::Record { log_record: sx("lr") }),
        ("Claim", DomainTuple::Claim { room_claim_core: sx("cc") }),
        ("ClaimDs", DomainTuple::ClaimDs { room_claim_core: sx("cc"), creator_signature: "csig".into() }),
        ("Genesis", DomainTuple::Genesis { room: "room-alpha".into(), genesis_blob_ref: sx("br"), creator_key: "@k".into() }),
        ("PredecessorOffer", DomainTuple::PredecessorOffer { successor_offer_core: sx("oc") }),
        ("SuccessorConsent", DomainTuple::SuccessorConsent { successor_offer: sx("o") }),
        ("SuccessorDs", DomainTuple::SuccessorDs { successor_proposal: sx("p") }),
        ("OfferHash", DomainTuple::OfferHash { successor_offer: sx("o") }),
        ("BridgeHash", DomainTuple::BridgeHash { successor_value: sx("v") }),
        ("ClosurePackageHash", DomainTuple::ClosurePackageHash { closure_package: sx("cp") }),
    ]
}

/// The full domain-separation matrix over the complete corrected inventory.
#[test]
fn all_15_tuples_are_domain_separated() {
    let kp = Ed25519Keypair::from_seed(&[7u8; 32]);
    let vk = kp.public_bytes();
    let tuples = all_15();
    assert_eq!(tuples.len(), 15, "the complete inventory is 15 tuples");

    // (tag, fields, sig) for each.
    let signed: Vec<(&'static str, Vec<SExpr>, [u8; 64])> = tuples
        .iter()
        .map(|(_, t)| (t.domain_tag(), t.fields(), t.sign(&kp)))
        .collect();

    // all 15 domain tags are distinct.
    let mut tags: Vec<&str> = signed.iter().map(|(tag, _, _)| *tag).collect();
    tags.sort_unstable();
    tags.dedup();
    assert_eq!(tags.len(), 15, "all 15 CON-002 domain tags must be distinct");

    let mut transplant_rejections = 0usize;
    for (tag_i, fields_i, sig_i) in &signed {
        // each tuple verifies under its OWN tag.
        assert!(verify_tuple(&vk, tag_i, fields_i, sig_i), "{tag_i}: own-tag signature must verify");
        // and under NONE of the other 14 tags (domain separation).
        for (tag_j, _, _) in &signed {
            if tag_j != tag_i {
                assert!(
                    !verify_tuple(&vk, tag_j, fields_i, sig_i),
                    "domain transplant {tag_i} -> {tag_j} must be rejected"
                );
                transplant_rejections += 1;
            }
        }
    }
    assert_eq!(transplant_rejections, 15 * 14, "the full 15x14 transplant matrix");
    println!("[TEST-024 o2] 15 distinct tags, 15 own-verifies, {transplant_rejections} transplant rejections");
}

/// Every tuple's signature is broken by mutating a field (or adding one to a field-free hash).
#[test]
fn every_tuple_signature_is_mutation_sensitive() {
    let kp = Ed25519Keypair::from_seed(&[7u8; 32]);
    let vk = kp.public_bytes();
    let mut checked = 0usize;
    for (name, t) in all_15() {
        let sig = t.sign(&kp);
        let tag = t.domain_tag();
        let mut fields = t.fields();
        // Mutate: append a sentinel field (changes the tuple's canonical bytes for any variant).
        fields.push(sx("MUTATION-SENTINEL"));
        assert!(!verify_tuple(&vk, tag, &fields, &sig), "{name}: a mutated preimage must not verify");
        checked += 1;
    }
    assert_eq!(checked, 15);
    println!("[TEST-024 o2] 15/15 tuples reject a mutated preimage");
}
