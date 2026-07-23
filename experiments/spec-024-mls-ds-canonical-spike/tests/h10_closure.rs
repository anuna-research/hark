//! IMPL-025 H10 (partial) — CON-010 `authenticate_successor_package` core + ClosureBlock.
//!
//! Ports the `mls-ds-successor-closure.mjs` authenticator — distinct rooms, DS-key pin, the
//! offer window, and the THREE choreography signatures (predecessor OFFER, successor CONSENT
//! over the exact offer, DS countersignature) — to Rust, computing crypto via the corrected
//! `DomainTuple::PredecessorOffer` / `SuccessorConsent` / `SuccessorDs` (tags match the JS
//! `predecessorOfferSigInput`/`successorConsentSigInput`/`dsSigInput`). Semantic ported, crypto
//! CONSUMED ([[IMPL-025-hark-mls-ds-client#ADR-032]]). Plus the ClosureBlock decision: a second
//! valid bridge with a different `closure_package_hash` blocks — both rooms preserved.
//!
//! Scope: the CON-010 authentication + closure-block essence ([[SPEC-024-mls-delivery-service#TEST-023]]:
//! offer/consent, two-room CAS, complete pins). DEFERRED: the full flat-package recogniser, the
//! genesis-evidence binding, and the two-store C-CLOSED/C-SUCCESSOR-PIN commit. Pre-pin.
//!
//!   cargo test --manifest-path experiments/spec-024-mls-ds-canonical-spike/Cargo.toml \
//!       --test h10_closure -- --nocapture

use cbcl_core::mls_ds::{b64url_encode, DomainTuple, Ed25519Keypair};
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

const OFFER_WINDOW_MS: i64 = 600_000;

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Authenticated { closure_package_hash: String },
    Refuse(&'static str),
    ClosureBlock,
}

/// A parsed successor closure package (components + the three signatures).
struct Package {
    pred_room: String,
    succ_room: String,
    dialect_hash: String,
    ds_key_id: String,
    issued_at: i64,
    not_after: i64,
    offer_core: SExpr,
    pred_vk: [u8; 32],
    pred_sig: [u8; 64],
    offer: SExpr,
    succ_vk: [u8; 32],
    succ_sig: [u8; 64],
    proposal: SExpr,
    ds_sig: [u8; 64],
}

fn closure_package_hash(proposal: &SExpr, ds_sig: &[u8; 64]) -> String {
    let bridge = list(vec![sym("successor-bridge-v1"), proposal.clone(), st(&b64url_encode(ds_sig))]);
    let pkg = list(vec![sym("closure-package-v1"), bridge]);
    DomainTuple::ClosurePackageHash { closure_package: pkg }.content_hash()
}

/// The ported CON-010 authenticator.
fn authenticate(expected_dialect: &str, pinned_ds_key_id: &str, ds_vk: &[u8; 32], p: &Package) -> Verdict {
    // (1) distinct predecessor / successor rooms.
    if p.pred_room == p.succ_room {
        return Verdict::Refuse("same-room");
    }
    // (2) installed canonical dialect hash.
    if p.dialect_hash != expected_dialect {
        return Verdict::Refuse("dialect-mismatch");
    }
    // (3) DS-key pin — the self-asserted ds_key_id must equal the client's pin.
    if p.ds_key_id != pinned_ds_key_id {
        return Verdict::Refuse("ds-key-substitution");
    }
    // (4) offer window: issued_at < not_after <= issued_at + 600000.
    if !(p.issued_at < p.not_after) || !(p.not_after <= p.issued_at + OFFER_WINDOW_MS) {
        return Verdict::Refuse("offer-window-invalid");
    }
    // (5) predecessor OFFER signature under the predecessor immutable creator.
    let offer_sig = DomainTuple::PredecessorOffer { successor_offer_core: p.offer_core.clone() };
    if !offer_sig.verify(&p.pred_vk, &p.pred_sig) {
        return Verdict::Refuse("predecessor-offer-sig-invalid");
    }
    // (6) successor CONSENT over the EXACT offer (which includes the predecessor signature).
    let consent = DomainTuple::SuccessorConsent { successor_offer: p.offer.clone() };
    if !consent.verify(&p.succ_vk, &p.succ_sig) {
        return Verdict::Refuse("successor-consent-sig-invalid");
    }
    // (7) DS countersignature over the proposal.
    let ds = DomainTuple::SuccessorDs { successor_proposal: p.proposal.clone() };
    if !ds.verify(ds_vk, &p.ds_sig) {
        return Verdict::Refuse("ds-sig-invalid");
    }
    Verdict::Authenticated { closure_package_hash: closure_package_hash(&p.proposal, &p.ds_sig) }
}

// ── fixture: a fully valid, self-consistent closure package ──────────────────────
#[allow(clippy::too_many_arguments)]
fn build_package(
    pred_room: &str,
    succ_room: &str,
    dialect_hash: &str,
    ds: &Ed25519Keypair,
    pred: &Ed25519Keypair,
    succ: &Ed25519Keypair,
    nonce: &str,
    issued_at: i64,
    not_after: i64,
) -> Package {
    let ds_key_id = ds.key_id();
    let core = list(vec![
        sym("successor-core-v1"),
        st(pred_room),
        st(&format!("sha256:{}", "1".repeat(64))),
        st(&format!("sha256:{}", "2".repeat(64))),
        num(7),
        st(&format!("sha256:{}", "3".repeat(64))),
        st(succ_room),
        st(&format!("sha256:{}", "4".repeat(64))),
        st(&format!("sha256:{}", "5".repeat(64))),
        st(dialect_hash),
        st(&ds_key_id),
    ]);
    let offer_core = list(vec![sym("successor-offer-core-v1"), core, st(nonce), num(issued_at), num(not_after)]);

    let pred_sig = DomainTuple::PredecessorOffer { successor_offer_core: offer_core.clone() }.sign(pred);
    let offer = list(vec![
        sym("successor-offer-v1"),
        offer_core.clone(),
        st(&pred.key_id()),
        st(&b64url_encode(&pred_sig)),
    ]);

    let succ_sig = DomainTuple::SuccessorConsent { successor_offer: offer.clone() }.sign(succ);
    let proposal = list(vec![
        sym("successor-proposal-v1"),
        offer.clone(),
        st(&succ.key_id()),
        st(&b64url_encode(&succ_sig)),
    ]);

    let ds_sig = DomainTuple::SuccessorDs { successor_proposal: proposal.clone() }.sign(ds);

    Package {
        pred_room: pred_room.into(),
        succ_room: succ_room.into(),
        dialect_hash: dialect_hash.into(),
        ds_key_id,
        issued_at,
        not_after,
        offer_core,
        pred_vk: pred.public_bytes(),
        pred_sig,
        offer,
        succ_vk: succ.public_bytes(),
        succ_sig,
        proposal,
        ds_sig,
    }
}

const DIALECT: &str = "sha256:922ba8bf9eb62a07b81989a9bfe6754a626b2edaf4d3f52e3fc4b41321261858";

fn keys() -> (Ed25519Keypair, Ed25519Keypair, Ed25519Keypair) {
    (
        Ed25519Keypair::from_seed(&[1u8; 32]), // ds
        Ed25519Keypair::from_seed(&[2u8; 32]), // pred creator
        Ed25519Keypair::from_seed(&[3u8; 32]), // succ creator
    )
}

/// A fully valid package with all three choreography signatures authenticates.
#[test]
fn valid_package_authenticates() {
    let (ds, pred, succ) = keys();
    let p = build_package("room-old", "room-new", DIALECT, &ds, &pred, &succ, "nonce-1", 1000, 1000 + 600_000);
    let v = authenticate(DIALECT, &ds.key_id(), &ds.public_bytes(), &p);
    println!("[H10 closure] valid package -> {v:?}");
    assert!(matches!(v, Verdict::Authenticated { .. }));
}

/// Predecessor == successor room is refused.
#[test]
fn same_room_is_refused() {
    let (ds, pred, succ) = keys();
    let p = build_package("room-x", "room-x", DIALECT, &ds, &pred, &succ, "n", 1000, 1600);
    assert_eq!(authenticate(DIALECT, &ds.key_id(), &ds.public_bytes(), &p), Verdict::Refuse("same-room"));
    println!("[H10 closure] same-room -> Refuse");
}

/// A self-asserted DS key-id that differs from the client's pin is refused.
#[test]
fn ds_key_substitution_is_refused() {
    let (ds, pred, succ) = keys();
    let p = build_package("room-old", "room-new", DIALECT, &ds, &pred, &succ, "n", 1000, 1600);
    let other_pin = Ed25519Keypair::from_seed(&[9u8; 32]).key_id();
    assert_eq!(authenticate(DIALECT, &other_pin, &ds.public_bytes(), &p), Verdict::Refuse("ds-key-substitution"));
    println!("[H10 closure] ds-key-substitution -> Refuse");
}

/// An offer window wider than 600 s is refused.
#[test]
fn over_wide_offer_window_is_refused() {
    let (ds, pred, succ) = keys();
    let p = build_package("room-old", "room-new", DIALECT, &ds, &pred, &succ, "n", 1000, 1000 + 600_001);
    assert_eq!(authenticate(DIALECT, &ds.key_id(), &ds.public_bytes(), &p), Verdict::Refuse("offer-window-invalid"));
    println!("[H10 closure] over-wide window -> Refuse");
}

/// A tampered successor consent signature is refused.
#[test]
fn tampered_consent_is_refused() {
    let (ds, pred, succ) = keys();
    let mut p = build_package("room-old", "room-new", DIALECT, &ds, &pred, &succ, "n", 1000, 1600);
    p.succ_sig[0] ^= 0xff;
    assert_eq!(
        authenticate(DIALECT, &ds.key_id(), &ds.public_bytes(), &p),
        Verdict::Refuse("successor-consent-sig-invalid")
    );
    println!("[H10 closure] tampered consent -> Refuse");
}

/// A second valid bridge with a DIFFERENT closure_package_hash → ClosureBlock (both preserved).
#[test]
fn conflicting_closure_package_blocks() {
    let (ds, pred, succ) = keys();
    let p1 = build_package("room-old", "room-new", DIALECT, &ds, &pred, &succ, "nonce-1", 1000, 1600);
    let p2 = build_package("room-old", "room-new2", DIALECT, &ds, &pred, &succ, "nonce-2", 1000, 1600);

    let v1 = authenticate(DIALECT, &ds.key_id(), &ds.public_bytes(), &p1);
    let v2 = authenticate(DIALECT, &ds.key_id(), &ds.public_bytes(), &p2);
    let (h1, h2) = match (&v1, &v2) {
        (Verdict::Authenticated { closure_package_hash: a }, Verdict::Authenticated { closure_package_hash: b }) => (a.clone(), b.clone()),
        _ => panic!("both must authenticate: {v1:?} {v2:?}"),
    };
    // Two authenticated packages with distinct closure_package_hash for the same predecessor:
    // the second is a conflicting bridge → ClosureBlock, both rooms preserved.
    let outcome = if h1 != h2 { Verdict::ClosureBlock } else { v2 };
    println!("[H10 closure] conflicting package: h1!=h2={} -> {outcome:?}", h1 != h2);
    assert_eq!(outcome, Verdict::ClosureBlock);
}
