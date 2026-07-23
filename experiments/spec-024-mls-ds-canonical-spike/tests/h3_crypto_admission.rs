//! IMPL-025 H3 (partial) — crypto-admission over the corrected `DomainTuple` API.
//!
//! This is the core of [[IMPL-025-hark-mls-ds-client#TEST-024]] oracle 2 (crypto admission)
//! and the [[IMPL-025-hark-mls-ds-client#ADR-032]] property that mattered most: **domain
//! separation** over the *corrected* CON-002 tuples. It consumes `cbcl-core::mls_ds`'s SOUND
//! crypto primitives — real Ed25519 under the REQ-141 strict profile and the typed
//! `DomainTuple` constructors whose tags/fields match CON-002 (e.g. `AddAuth` →
//! `"mls-add-authorization-v1"` WITH `room`, not the JS proof's divergent `mls-ds-add-auth-v1`).
//!
//! Scope: it does **not** consume the DS-branch recogniser (still a subset with `Other`
//! shells — the one genuinely non-production piece). Pre-pin experiment (ADR-021); the
//! substrate is the DS-branch worktree (epp `febc669` + 5 mls-ds commits).
//!
//!   cargo test --manifest-path experiments/spec-024-mls-ds-canonical-spike/Cargo.toml \
//!       --test h3_crypto_admission -- --nocapture

use cbcl_core::mls_ds::{scalar_is_canonical, verify_tuple, DomainTuple, Ed25519Keypair};
use cbcl_core::sexpr::{Atom, SExpr};

fn digest(nib: &str) -> String {
    format!("sha256:{}", nib.repeat(64))
}

fn add_auth() -> DomainTuple {
    // The 9-field add-authorization tuple with the CORRECTED tag + room (ADR-032).
    DomainTuple::AddAuth {
        room: "room-alpha".into(),
        source_author_key: "@creator-author-key".into(),
        base_seq: 41,
        base_hash: digest("a"),
        ciphertext_digest: digest("b"),
        targets: vec!["@alice".into(), "@bob".into()],
        welcome_digest: digest("c"),
        genesis_anchor_hash: digest("d"),
    }
}

/// The corrected tag is what CON-002 signs — not the JS proof's divergent form.
#[test]
fn add_auth_carries_the_corrected_con002_domain_tag() {
    assert_eq!(
        add_auth().domain_tag(),
        "mls-add-authorization-v1",
        "ADR-032: the reconciled tag is mls-add-authorization-v1 (with room), not mls-ds-add-auth-v1"
    );
}

/// A valid signature verifies; a domain transplant and a field mutation are rejected.
#[test]
fn valid_signature_verifies_transplant_and_mutation_rejected() {
    let kp = Ed25519Keypair::from_seed(&[7u8; 32]);
    let vk = kp.public_bytes();
    let t = add_auth();
    let sig = t.sign(&kp);

    // positive — method form and free-fn form agree
    assert!(t.verify(&vk, &sig), "a valid AddAuth signature must verify under the strict profile");
    assert!(
        verify_tuple(&vk, t.domain_tag(), &t.fields(), &sig),
        "free-fn verify_tuple must agree with DomainTuple::verify"
    );
    println!("[H3 crypto] AddAuth valid-sig verify = OK  tag={}", t.domain_tag());

    // domain transplant — SAME fields + sig under a DIFFERENT domain tag must be rejected
    for wrong in [
        "mls-ds-record-signature-v1",
        "mls-ds-source-signature-v1",
        "mls-genesis-signature-v1",
        "mls-ds-successor-hash-v1",
    ] {
        assert!(
            !verify_tuple(&vk, wrong, &t.fields(), &sig),
            "domain transplant to `{wrong}` must be rejected (domain separation)"
        );
    }
    println!("[H3 crypto] domain-transplant across 4 foreign tags = all REJECTED");

    // field mutation — flip fields[0] (the room `room-alpha`) and re-verify under the right tag
    let mut mutated = t.fields();
    mutated[0] = SExpr::Atom(Atom::Str("room-beta".into()));
    assert!(
        !verify_tuple(&vk, t.domain_tag(), &mutated, &sig),
        "a one-field mutation must invalidate the signature"
    );
    println!("[H3 crypto] field mutation (room-alpha -> room-beta) = REJECTED");
}

/// A signature does not verify under a different verifying key.
#[test]
fn signature_does_not_verify_under_a_foreign_key() {
    let kp = Ed25519Keypair::from_seed(&[7u8; 32]);
    let foreign = Ed25519Keypair::from_seed(&[9u8; 32]).public_bytes();
    let t = DomainTuple::Source {
        source: SExpr::Atom(Atom::Str("source-bytes".into())),
    };
    let sig = t.sign(&kp);
    assert!(t.verify(&kp.public_bytes(), &sig), "own key verifies");
    assert!(!t.verify(&foreign, &sig), "a foreign key must not verify the signature");
    println!("[H3 crypto] foreign-key verify = REJECTED");
}

/// REQ-141 strict profile: an out-of-range scalar is non-canonical.
#[test]
fn ed25519_strict_profile_rejects_out_of_range_scalar() {
    assert!(scalar_is_canonical(&[0u8; 32]), "0 < L is a canonical scalar");
    assert!(
        !scalar_is_canonical(&[0xffu8; 32]),
        "2^256-1 exceeds the group order L — non-canonical (REQ-141 malleability rejection)"
    );
    println!("[H3 crypto] canonical-scalar gate: 0=OK, 0xff*32=REJECTED");
}

/// The closure-pin hashes are deterministic, domain-tagged, and mutation-sensitive —
/// the specifically-flagged [[IMPL-025-hark-mls-ds-client#TEST-025]] closure-preimage
/// mutation case (review R-01): a mutated `bridge_hash` / `closure_package_hash` must not
/// collide with the original, and the two hash domains must not collide on the same value.
#[test]
fn closure_preimage_hashes_are_domain_tagged_and_mutation_sensitive() {
    let value = SExpr::List(vec![
        SExpr::Atom(Atom::Str("successor-alpha".into())),
        SExpr::Atom(Atom::Num(7)),
    ]);
    let bridge = DomainTuple::BridgeHash { successor_value: value.clone() };
    let package = DomainTuple::ClosurePackageHash { closure_package: value.clone() };

    // domain tags are the corrected CON-002 ones
    assert_eq!(bridge.domain_tag(), "mls-ds-successor-hash-v1");
    assert_eq!(package.domain_tag(), "mls-ds-closure-package-hash-v1");

    // deterministic
    assert_eq!(
        bridge.content_hash(),
        DomainTuple::BridgeHash { successor_value: value.clone() }.content_hash()
    );

    // domain separation: SAME value under the two hash domains must not collide
    assert_ne!(
        bridge.content_hash(),
        package.content_hash(),
        "bridge_hash and closure_package_hash must not collide on the same value"
    );

    // mutation sensitivity: one changed field -> a different hash, for both domains
    let mutated = SExpr::List(vec![
        SExpr::Atom(Atom::Str("successor-BETA".into())),
        SExpr::Atom(Atom::Num(7)),
    ]);
    assert_ne!(
        bridge.content_hash(),
        DomainTuple::BridgeHash { successor_value: mutated.clone() }.content_hash(),
        "a mutated bridge_hash preimage must produce a different hash"
    );
    assert_ne!(
        package.content_hash(),
        DomainTuple::ClosurePackageHash { closure_package: mutated }.content_hash(),
        "a mutated closure_package_hash preimage must produce a different hash"
    );
    println!("[H3 crypto] closure hashes: deterministic + domain-tagged + mutation-sensitive = OK");
}
