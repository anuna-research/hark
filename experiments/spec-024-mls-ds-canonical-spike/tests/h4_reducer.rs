//! IMPL-025 H4 (partial) — CON-005 `transition_client` exact-next admission core.
//!
//! Ports the `mls-ds-client-reducer.mjs` ORDERING logic — record-hash recompute, DS-signature
//! authenticity, the REQ-034 positional **exact-next** clause, the `C-APPLIED` cursor advance,
//! and the cursor **hold** on a non-exact-next record — to Rust, computing crypto via the
//! CORRECTED `DomainTuple::Record` (`mls-ds-record-signature-v1` wrapper; the JS proof signs
//! the bare record, [[IMPL-025-hark-mls-ds-client#ADR-032]]). Semantic/ordering ported, crypto
//! CONSUMED.
//!
//! Scope: the exact-next pull ordering that forbids live/replay interleave
//! ([[SPEC-024-mls-delivery-service#TEST-014]]: exact-next pull, cursor block). DEFERRED to the
//! fuller H4: the whole header↔source transplant binding (source_hash/base/targets/payload),
//! Add-authorization, welcome/ack, C-REBASE, recovery, and the closure phases. Pre-pin.
//!
//!   cargo test --manifest-path experiments/spec-024-mls-ds-canonical-spike/Cargo.toml \
//!       --test h4_reducer -- --nocapture

use cbcl_core::canonical::canonical_encode;
use cbcl_core::mls_ds::{DomainTuple, Ed25519Keypair};
use cbcl_core::sexpr::{Atom, SExpr};
use sha2::{Digest, Sha256};

fn sym(s: &str) -> SExpr {
    SExpr::Atom(Atom::Symbol(s.into()))
}
fn st(s: &str) -> SExpr {
    SExpr::Atom(Atom::Str(s.into()))
}
fn num(n: i64) -> SExpr {
    SExpr::Atom(Atom::Num(n))
}

fn hexs(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}
/// The bare record content hash (the cursor chain link) — `sha256:` + hex(SHA-256(canon(rec))).
fn record_hash(rec: &SExpr) -> String {
    format!("sha256:{}", hexs(&Sha256::digest(canonical_encode(rec))))
}

#[derive(Clone)]
struct ClientLog {
    cursor: i64,
    cursor_hash: String,
}

/// A verified DS response carrying a log record (post-CON-012 authentication).
struct Response {
    seq: i64,
    prev_hash: String,
    record_hash: String,
    record_signature: [u8; 64],
    log_record: SExpr,
}

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// C-APPLIED: cursor advances by one, cursor_hash := record_hash.
    Applied { cursor: i64, cursor_hash: String },
    /// notNext (REQ-034 negative): cursor preserved, no effect.
    NotNext,
    /// Violation(ds-equivocation): cursor + group held, bytes retained as fork evidence.
    Violation(&'static str),
}

/// The ported CON-005 record-admission core.
fn transition_client(log: &ClientLog, ds_vk: &[u8; 32], resp: &Response) -> Verdict {
    // (1) recomputed record identity (authenticity of the header content).
    if record_hash(&resp.log_record) != resp.record_hash {
        return Verdict::Violation("ds-equivocation:record-hash-mismatch");
    }
    // (2) DS signature over the CORRECTED record-signature tuple.
    let record = DomainTuple::Record { log_record: resp.log_record.clone() };
    if !record.verify(ds_vk, &resp.record_signature) {
        return Verdict::Violation("ds-equivocation:record-signature-invalid");
    }
    // (5) positional exact-next clause (REQ-034). Only this failing ⇒ notNext (cursor held).
    if !(resp.seq == log.cursor + 1 && resp.prev_hash == log.cursor_hash) {
        return Verdict::NotNext;
    }
    // C-APPLIED — advance by exactly one; the new cursor_hash is this record's hash.
    Verdict::Applied {
        cursor: resp.seq,
        cursor_hash: resp.record_hash.clone(),
    }
}

// ── fixture: a valid DS-signed record at (seq, prev_hash) ────────────────────────
fn signed_record(seq: i64, prev_hash: &str, ds: &Ed25519Keypair) -> Response {
    let rec = SExpr::List(vec![sym("log-v1"), st("room-alpha"), num(seq), st(prev_hash)]);
    let rh = record_hash(&rec);
    let sig = DomainTuple::Record { log_record: rec.clone() }.sign(ds);
    Response {
        seq,
        prev_hash: prev_hash.into(),
        record_hash: rh,
        record_signature: sig,
        log_record: rec,
    }
}

const H0: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// An exact-next, DS-signed record advances the cursor by one (C-APPLIED).
#[test]
fn exact_next_record_is_applied_and_advances_the_cursor() {
    let ds = Ed25519Keypair::from_seed(&[5u8; 32]);
    let log = ClientLog { cursor: 0, cursor_hash: H0.into() };
    let resp = signed_record(1, H0, &ds);
    let v = transition_client(&log, &ds.public_bytes(), &resp);
    println!("[H4 reducer] exact-next seq=1 -> {v:?}");
    assert!(matches!(v, Verdict::Applied { cursor: 1, .. }));
}

/// The cursor chains: after applying seq=1, seq=2 whose prev_hash is seq=1's record_hash applies.
#[test]
fn cursor_chains_across_two_records() {
    let ds = Ed25519Keypair::from_seed(&[5u8; 32]);
    let vk = ds.public_bytes();
    let r1 = signed_record(1, H0, &ds);
    let log1 = match transition_client(&ClientLog { cursor: 0, cursor_hash: H0.into() }, &vk, &r1) {
        Verdict::Applied { cursor, cursor_hash } => ClientLog { cursor, cursor_hash },
        other => panic!("expected Applied, got {other:?}"),
    };
    let r2 = signed_record(2, &log1.cursor_hash, &ds);
    let v = transition_client(&log1, &vk, &r2);
    println!("[H4 reducer] chained seq=2 -> {v:?}");
    assert!(matches!(v, Verdict::Applied { cursor: 2, .. }));
}

/// A sequence gap (seq=2 at cursor 0) holds the cursor — notNext (no live/replay interleave).
#[test]
fn a_sequence_gap_holds_the_cursor() {
    let ds = Ed25519Keypair::from_seed(&[5u8; 32]);
    let log = ClientLog { cursor: 0, cursor_hash: H0.into() };
    let resp = signed_record(2, H0, &ds);
    let v = transition_client(&log, &ds.public_bytes(), &resp);
    println!("[H4 reducer] gap seq=2@cursor0 -> {v:?}");
    assert_eq!(v, Verdict::NotNext);
}

/// A correct seq but wrong prev_hash also holds the cursor (fork detection via the chain).
#[test]
fn wrong_prev_hash_holds_the_cursor() {
    let ds = Ed25519Keypair::from_seed(&[5u8; 32]);
    let log = ClientLog { cursor: 0, cursor_hash: H0.into() };
    let resp = signed_record(1, "sha256:beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef", &ds);
    let v = transition_client(&log, &ds.public_bytes(), &resp);
    println!("[H4 reducer] wrong prev_hash -> {v:?}");
    assert_eq!(v, Verdict::NotNext);
}

/// A record signed by a non-DS key is ds-equivocation (cursor + group held).
#[test]
fn foreign_signed_record_is_equivocation() {
    let ds = Ed25519Keypair::from_seed(&[5u8; 32]);
    let forger = Ed25519Keypair::from_seed(&[6u8; 32]);
    let log = ClientLog { cursor: 0, cursor_hash: H0.into() };
    let resp = signed_record(1, H0, &forger); // signed by the wrong key
    let v = transition_client(&log, &ds.public_bytes(), &resp);
    println!("[H4 reducer] foreign-signed record -> {v:?}");
    assert_eq!(v, Verdict::Violation("ds-equivocation:record-signature-invalid"));
}

/// A record whose advertised record_hash does not match its content is ds-equivocation.
#[test]
fn record_hash_mismatch_is_equivocation() {
    let ds = Ed25519Keypair::from_seed(&[5u8; 32]);
    let log = ClientLog { cursor: 0, cursor_hash: H0.into() };
    let mut resp = signed_record(1, H0, &ds);
    resp.record_hash = "sha256:1111111111111111111111111111111111111111111111111111111111111111".into();
    let v = transition_client(&log, &ds.public_bytes(), &resp);
    println!("[H4 reducer] record-hash mismatch -> {v:?}");
    assert_eq!(v, Verdict::Violation("ds-equivocation:record-hash-mismatch"));
}
