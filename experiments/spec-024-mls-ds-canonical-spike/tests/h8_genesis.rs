//! IMPL-025 H8 / H4 (partial) — CON-008 genesis validation DECISION port.
//!
//! Ports the `mls-ds-genesis-validator.mjs` VERDICT logic — the transplant guard, the
//! three-signature verification, and the **singleton + locally-derived-grade** rule — to
//! Rust, computing every crypto preimage via the `DomainTuple` API (`Claim` / `ClaimDs` /
//! `Genesis`, whose tags match the JS `claimSigMsg`/`claimDsSigMsg`/`genesisSigMsg`). Per
//! [[IMPL-025-hark-mls-ds-client#ADR-032]] this ports the SEMANTIC/ordering logic only; the
//! crypto is CONSUMED, never re-derived.
//!
//! Scope (honest): this proves the CON-008 DECISION that gates the PreGenesis→Open store
//! (acceptance [[SPEC-024-mls-delivery-service#TEST-016]]: room claim, singleton anchor,
//! grade lie, transplant). It is self-consistent (signs + verifies through one encoding).
//! DEFERRED: the full byte-grammar recogniser (the non-production gap) and the exact
//! production genesis-register preimage layout — the anchor id here is an injective
//! domain-tagged hash over (core, blob_ref), enough for the singleton decision. Pre-pin.
//!
//!   cargo test --manifest-path experiments/spec-024-mls-ds-canonical-spike/Cargo.toml \
//!       --test h8_genesis -- --nocapture

use cbcl_core::mls_ds::{b64url_encode, tuple_content_hash, DomainTuple, Ed25519Keypair};
use cbcl_core::sexpr::{Atom, SExpr};

fn sym(s: &str) -> SExpr {
    SExpr::Atom(Atom::Symbol(s.into()))
}
fn st(s: &str) -> SExpr {
    SExpr::Atom(Atom::Str(s.into()))
}
fn num(n: i64) -> SExpr {
    SExpr::Atom(Atom::Num(n))
}
fn list(v: Vec<SExpr>) -> SExpr {
    SExpr::List(v)
}

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    FirstAccepted { grade: &'static str, anchor_hash: String },
    Existing { anchor_hash: String },
    Conflict(&'static str),
}

/// A decoded genesis candidate (post-recognition — the recogniser is out of scope here).
struct Candidate {
    room: String,
    grade: &'static str, // "tofu" | "verified"
    creator_key: String, // @base64url — equals the CLAIM/GENESIS signer's key-id
    link_room: String,
    link_creator_key: String,
    room_claim_core: SExpr,
    creator_sig: [u8; 64],
    ds_sig: [u8; 64],
    genesis_blob_ref: SExpr,
    genesis_sig: [u8; 64],
}

/// Injective domain-tagged anchor id over the core identity (mirrors the JS `anchorHash`
/// shape; simplified to (core, blob_ref) for the singleton decision).
fn anchor_hash(core: &SExpr, blob_ref: &SExpr) -> String {
    tuple_content_hash("mls-genesis-anchor-hash-v1", &[core.clone(), blob_ref.clone()])
}

/// The ported CON-008 decision (Phases A2, C, E, F of the JS validator).
fn validate_genesis(
    saved_anchor: Option<&str>,
    expected_room: &str,
    creator_vk: &[u8; 32],
    ds_vk: &[u8; 32],
    c: &Candidate,
) -> Verdict {
    // Phase A2 — room/key agreement (the transplant guard).
    if c.room != expected_room || c.link_room != expected_room {
        return Verdict::Conflict("room-transplant");
    }
    if c.link_creator_key != c.creator_key {
        return Verdict::Conflict("key-transplant");
    }

    // Phase C — REAL Ed25519 verification of the three canonical signatures, via DomainTuple.
    let claim = DomainTuple::Claim { room_claim_core: c.room_claim_core.clone() };
    if !claim.verify(creator_vk, &c.creator_sig) {
        return Verdict::Conflict("claim-sig-invalid");
    }
    let claim_ds = DomainTuple::ClaimDs {
        room_claim_core: c.room_claim_core.clone(),
        creator_signature: b64url_encode(&c.creator_sig),
    };
    if !claim_ds.verify(ds_vk, &c.ds_sig) {
        return Verdict::Conflict("claim-ds-sig-invalid");
    }
    let genesis = DomainTuple::Genesis {
        room: c.room.clone(),
        genesis_blob_ref: c.genesis_blob_ref.clone(),
        creator_key: c.creator_key.clone(),
    };
    if !genesis.verify(creator_vk, &c.genesis_sig) {
        return Verdict::Conflict("genesis-sig-invalid");
    }

    // Phase E — the anchor id (never the DS wire grade) is the stored value.
    let anchor = anchor_hash(&c.room_claim_core, &c.genesis_blob_ref);

    // Phase F — singleton + locally-derived grade.
    match saved_anchor {
        Some(saved) => {
            // A DIFFERENT validly-signed anchor is equivocation, NOT an extension.
            if anchor != saved {
                return Verdict::Conflict("saved-anchor-mismatch");
            }
            if c.grade != "verified" {
                return Verdict::Conflict("grade-contradiction");
            }
            Verdict::Existing { anchor_hash: anchor }
        }
        None => {
            // First contact: a DS `verified` label with nothing saved is a grade lie.
            if c.grade != "tofu" {
                return Verdict::Conflict("grade-lie");
            }
            Verdict::FirstAccepted { grade: "tofu", anchor_hash: anchor }
        }
    }
}

// ── fixture: a fully valid, self-consistent genesis candidate ────────────────────
fn build_valid(room: &str, grade: &'static str, creator: &Ed25519Keypair, ds: &Ed25519Keypair) -> Candidate {
    let creator_key = creator.key_id();
    let core = list(vec![
        sym("room-claim-v1"),
        st(room),
        st("Room Label"),
        sym(&creator_key),
        num(1),
        st("meta"),
    ]);
    let claim = DomainTuple::Claim { room_claim_core: core.clone() };
    let creator_sig = claim.sign(creator);
    let claim_ds = DomainTuple::ClaimDs {
        room_claim_core: core.clone(),
        creator_signature: b64url_encode(&creator_sig),
    };
    let ds_sig = claim_ds.sign(ds);
    let blob_ref = list(vec![
        sym("blob-ref-v1"),
        sym("genesis"),
        st(&format!("sha256:{}", "a".repeat(64))),
        num(64),
    ]);
    let genesis = DomainTuple::Genesis {
        room: room.into(),
        genesis_blob_ref: blob_ref.clone(),
        creator_key: creator_key.clone(),
    };
    let genesis_sig = genesis.sign(creator);
    Candidate {
        room: room.into(),
        grade,
        creator_key: creator_key.clone(),
        link_room: room.into(),
        link_creator_key: creator_key,
        room_claim_core: core,
        creator_sig,
        ds_sig,
        genesis_blob_ref: blob_ref,
        genesis_sig,
    }
}

fn keys() -> (Ed25519Keypair, Ed25519Keypair, [u8; 32], [u8; 32]) {
    let creator = Ed25519Keypair::from_seed(&[3u8; 32]);
    let ds = Ed25519Keypair::from_seed(&[5u8; 32]);
    let cvk = creator.public_bytes();
    let dvk = ds.public_bytes();
    (creator, ds, cvk, dvk)
}

/// First contact with a locally-derived `tofu` candidate → FirstAccepted.
#[test]
fn first_contact_tofu_is_accepted() {
    let (creator, ds, cvk, dvk) = keys();
    let c = build_valid("room-alpha", "tofu", &creator, &ds);
    let v = validate_genesis(None, "room-alpha", &cvk, &dvk, &c);
    println!("[H8 genesis] first-contact tofu -> {v:?}");
    assert!(matches!(v, Verdict::FirstAccepted { grade: "tofu", .. }));
}

/// A saved anchor + byte-identical `verified` candidate → Existing (no re-accept).
#[test]
fn saved_anchor_verified_reload_is_existing() {
    let (creator, ds, cvk, dvk) = keys();
    let c = build_valid("room-alpha", "verified", &creator, &ds);
    let saved = anchor_hash(&c.room_claim_core, &c.genesis_blob_ref);
    let v = validate_genesis(Some(&saved), "room-alpha", &cvk, &dvk, &c);
    println!("[H8 genesis] saved==anchor verified -> {v:?}");
    assert!(matches!(v, Verdict::Existing { .. }));
}

/// The SINGLETON rule: a saved anchor + a DIFFERENT validly-signed anchor → conflict,
/// never an extension.
#[test]
fn singleton_a_different_valid_anchor_is_a_conflict() {
    let (creator, ds, cvk, dvk) = keys();
    let c = build_valid("room-alpha", "verified", &creator, &ds);
    let v = validate_genesis(Some("sha256:deadbeef"), "room-alpha", &cvk, &dvk, &c);
    println!("[H8 genesis] singleton (saved != anchor) -> {v:?}");
    assert_eq!(v, Verdict::Conflict("saved-anchor-mismatch"));
}

/// A DS `verified` label on first contact is a grade lie → conflict.
#[test]
fn grade_lie_verified_on_first_contact_is_rejected() {
    let (creator, ds, cvk, dvk) = keys();
    let c = build_valid("room-alpha", "verified", &creator, &ds);
    let v = validate_genesis(None, "room-alpha", &cvk, &dvk, &c);
    println!("[H8 genesis] grade lie (verified, nothing saved) -> {v:?}");
    assert_eq!(v, Verdict::Conflict("grade-lie"));
}

/// The transplant guard: the link's creator key differs from the claim creator → conflict.
#[test]
fn key_transplant_is_rejected() {
    let (creator, ds, cvk, dvk) = keys();
    let mut c = build_valid("room-alpha", "tofu", &creator, &ds);
    c.link_creator_key = "@AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into();
    let v = validate_genesis(None, "room-alpha", &cvk, &dvk, &c);
    println!("[H8 genesis] key transplant -> {v:?}");
    assert_eq!(v, Verdict::Conflict("key-transplant"));
}

/// A tampered claim signature → conflict (effect-free, no anchor).
#[test]
fn tampered_claim_signature_is_rejected() {
    let (creator, ds, cvk, dvk) = keys();
    let mut c = build_valid("room-alpha", "tofu", &creator, &ds);
    c.creator_sig[0] ^= 0xff;
    let v = validate_genesis(None, "room-alpha", &cvk, &dvk, &c);
    println!("[H8 genesis] tampered claim sig -> {v:?}");
    assert_eq!(v, Verdict::Conflict("claim-sig-invalid"));
}
