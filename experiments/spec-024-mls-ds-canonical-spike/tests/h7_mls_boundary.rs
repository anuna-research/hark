//! IMPL-025 H7 (partial) — CON-006 MLS-boundary validation decisions.
//!
//! Implements the recogniser-free H7 decisions from
//! [[IMPL-025-hark-mls-ds-client#H7 — MLS semantic boundary realign]]:
//!   • **v1 owner-removal rejection** — a commit removing the room's immutable owner is
//!     deterministically rejected ([[SPEC-024-mls-delivery-service#REQ-098]], RFC 9420 §12.2).
//!   • **ADD-AUTH ↔ membership-delta consistency** — an Add commit's creator admission proof
//!     (`DomainTuple::AddAuth`) must authorise EXACTLY the added members, and a non-Add commit
//!     must carry NO add-authorization.
//!
//! Crypto CONSUMED via `DomainTuple::AddAuth` (the corrected `mls-add-authorization-v1` tuple).
//! Acceptance essence of [[SPEC-024-mls-delivery-service#TEST-020]] (immutable owner/creator
//! alignment, owner-removal rejection). Does NOT delete the legacy carve-out (post-H10 gate,
//! [[IMPL-025-hark-mls-ds-client#ADR-034]]). No recogniser needed. Pre-pin.
//!
//!   cargo test --manifest-path experiments/spec-024-mls-ds-canonical-spike/Cargo.toml \
//!       --test h7_mls_boundary -- --nocapture

use cbcl_core::mls_ds::{DomainTuple, Ed25519Keypair};

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Accept,
    Reject(&'static str),
}

/// A creator admission proof mirroring the `DomainTuple::AddAuth` fields + its signature.
struct AddAuth {
    room: String,
    source_author_key: String,
    base_seq: i64,
    base_hash: String,
    ciphertext_digest: String,
    targets: Vec<String>,
    welcome_digest: String,
    genesis_anchor_hash: String,
    sig: [u8; 64],
}

/// A modelled MLS commit's membership delta.
struct Commit {
    added: Vec<String>,
    removed: Vec<String>,
    add_auth: Option<AddAuth>,
}

fn sorted(v: &[String]) -> Vec<String> {
    let mut v = v.to_vec();
    v.sort();
    v
}

/// The H7 v1 commit validation decision.
fn validate_v1_commit(owner: &str, creator_vk: &[u8; 32], c: &Commit) -> Verdict {
    // REQ-098 — an owner self/other removal is deterministically rejected. Immutable owner.
    if c.removed.iter().any(|k| k == owner) {
        return Verdict::Reject("owner-removal-rejected");
    }
    let is_add = !c.added.is_empty();
    match (&c.add_auth, is_add) {
        (Some(auth), true) => {
            // Re-verify the admission proof under the immutable creator over the corrected tuple.
            let tuple = DomainTuple::AddAuth {
                room: auth.room.clone(),
                source_author_key: auth.source_author_key.clone(),
                base_seq: auth.base_seq,
                base_hash: auth.base_hash.clone(),
                ciphertext_digest: auth.ciphertext_digest.clone(),
                targets: auth.targets.clone(),
                welcome_digest: auth.welcome_digest.clone(),
                genesis_anchor_hash: auth.genesis_anchor_hash.clone(),
            };
            if !tuple.verify(creator_vk, &auth.sig) {
                return Verdict::Reject("add-auth-sig-invalid");
            }
            // ADD-AUTH ↔ membership-delta: the proof must authorise EXACTLY the added set.
            if sorted(&c.added) != sorted(&auth.targets) {
                return Verdict::Reject("add-auth-membership-mismatch");
            }
            Verdict::Accept
        }
        (None, true) => Verdict::Reject("add-missing-authorization"),
        (Some(_), false) => Verdict::Reject("non-add-carries-add-auth"),
        (None, false) => Verdict::Accept, // a plain (non-owner) removal / update
    }
}

fn digest(nib: &str) -> String {
    format!("sha256:{}", nib.repeat(64))
}

/// Build a valid ADD-AUTH authorising `targets`, signed by `creator`.
fn add_auth_for(targets: &[&str], creator: &Ed25519Keypair) -> AddAuth {
    let targets: Vec<String> = targets.iter().map(|s| s.to_string()).collect();
    let tuple = DomainTuple::AddAuth {
        room: "room-alpha".into(),
        source_author_key: creator.key_id(),
        base_seq: 4,
        base_hash: digest("a"),
        ciphertext_digest: digest("b"),
        targets: targets.clone(),
        welcome_digest: digest("c"),
        genesis_anchor_hash: digest("d"),
    };
    let sig = tuple.sign(creator);
    AddAuth {
        room: "room-alpha".into(),
        source_author_key: creator.key_id(),
        base_seq: 4,
        base_hash: digest("a"),
        ciphertext_digest: digest("b"),
        targets,
        welcome_digest: digest("c"),
        genesis_anchor_hash: digest("d"),
        sig,
    }
}

const OWNER: &str = "@owner-immutable-creator-key";

/// A commit that removes the immutable owner is rejected (REQ-098).
#[test]
fn owner_removal_is_deterministically_rejected() {
    let creator = Ed25519Keypair::from_seed(&[2u8; 32]);
    let c = Commit { added: vec![], removed: vec![OWNER.into()], add_auth: None };
    let v = validate_v1_commit(OWNER, &creator.public_bytes(), &c);
    println!("[H7 mls] owner removal -> {v:?}");
    assert_eq!(v, Verdict::Reject("owner-removal-rejected"));
}

/// A valid Add whose ADD-AUTH authorises exactly the added members is accepted.
#[test]
fn valid_add_with_matching_authorization_is_accepted() {
    let creator = Ed25519Keypair::from_seed(&[2u8; 32]);
    let auth = add_auth_for(&["@alice", "@bob"], &creator);
    let c = Commit { added: vec!["@bob".into(), "@alice".into()], removed: vec![], add_auth: Some(auth) };
    let v = validate_v1_commit(OWNER, &creator.public_bytes(), &c);
    println!("[H7 mls] valid Add (targets match) -> {v:?}");
    assert_eq!(v, Verdict::Accept);
}

/// An Add whose authorised targets differ from the actual added members is rejected.
#[test]
fn add_with_membership_mismatch_is_rejected() {
    let creator = Ed25519Keypair::from_seed(&[2u8; 32]);
    let auth = add_auth_for(&["@alice"], &creator); // authorises only alice
    let c = Commit { added: vec!["@alice".into(), "@mallory".into()], removed: vec![], add_auth: Some(auth) };
    let v = validate_v1_commit(OWNER, &creator.public_bytes(), &c);
    println!("[H7 mls] Add targets mismatch (mallory smuggled) -> {v:?}");
    assert_eq!(v, Verdict::Reject("add-auth-membership-mismatch"));
}

/// An Add whose ADD-AUTH is signed by a non-creator key is rejected.
#[test]
fn add_with_forged_authorization_is_rejected() {
    let creator = Ed25519Keypair::from_seed(&[2u8; 32]);
    let forger = Ed25519Keypair::from_seed(&[8u8; 32]);
    let auth = add_auth_for(&["@alice"], &forger); // signed by the wrong key
    let c = Commit { added: vec!["@alice".into()], removed: vec![], add_auth: Some(auth) };
    let v = validate_v1_commit(OWNER, &creator.public_bytes(), &c);
    println!("[H7 mls] Add with forged auth -> {v:?}");
    assert_eq!(v, Verdict::Reject("add-auth-sig-invalid"));
}

/// A non-Add commit that carries an add-authorization is rejected; an Add with none is rejected.
#[test]
fn add_auth_presence_must_match_commit_kind() {
    let creator = Ed25519Keypair::from_seed(&[2u8; 32]);
    let vk = creator.public_bytes();

    // non-Add (a plain removal) carrying add-auth
    let auth = add_auth_for(&["@alice"], &creator);
    let c1 = Commit { added: vec![], removed: vec!["@carol".into()], add_auth: Some(auth) };
    assert_eq!(validate_v1_commit(OWNER, &vk, &c1), Verdict::Reject("non-add-carries-add-auth"));

    // an Add with no authorization
    let c2 = Commit { added: vec!["@dave".into()], removed: vec![], add_auth: None };
    assert_eq!(validate_v1_commit(OWNER, &vk, &c2), Verdict::Reject("add-missing-authorization"));

    // a plain non-owner removal is fine
    let c3 = Commit { added: vec![], removed: vec!["@carol".into()], add_auth: None };
    assert_eq!(validate_v1_commit(OWNER, &vk, &c3), Verdict::Accept);
    println!("[H7 mls] add-auth presence ↔ commit-kind enforced; plain non-owner removal OK");
}
