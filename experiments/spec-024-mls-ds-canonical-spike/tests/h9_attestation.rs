//! IMPL-025 H9 (partial) — CON-009 attestation `contiguousHead` + suspect-vs-fork.
//!
//! Ports the two PURE decision functions of `mls-ds-attestation.mjs`:
//!   • `contiguousHead` — from a verified floor checkpoint, walk ONLY the contiguous signed
//!     header range, stop at the first hole or link break (REQ-065). Crypto-free.
//!   • the `compareAttestation` verdict core — agree / pending (no local coverage) and, on a
//!     head conflict, **suspect** (lone-peer, non-blocking) vs **fork** (DS-corroborated,
//!     blocking). This is the CON-009 head-evidence decision.
//!
//! Per [[IMPL-025-hark-mls-ds-client#ADR-032]] this ports the SEMANTIC/ordering logic; the
//! attestation byte recogniser + signature verification are CONSUMED from cbcl-rs, not ported
//! (out of scope here — see H9/F-07). Scope essence of [[SPEC-024-mls-delivery-service#TEST-019]]
//! (contiguous attestation, suspect vs fork). Pre-pin.
//!
//!   cargo test --manifest-path experiments/spec-024-mls-ds-canonical-spike/Cargo.toml \
//!       --test h9_attestation -- --nocapture

use std::collections::BTreeMap;

/// records: seq -> (prev_hash, record_hash). A verified, DS-signed contiguous range.
type Records = BTreeMap<i64, (String, String)>;

/// contiguousHead (REQ-065). Starts at the signed floor checkpoint and returns the last
/// (seq, hash) reachable by an unbroken prev_hash→record_hash chain.
fn contiguous_head(floor: i64, floor_prev: &str, records: &Records) -> (i64, String) {
    match records.get(&floor) {
        // Empty / full-compaction, or the record at the floor doesn't link to floor_prev.
        None => (floor - 1, floor_prev.to_string()),
        Some((prev, _)) if prev != floor_prev => (floor - 1, floor_prev.to_string()),
        Some((_, rh)) => {
            let mut seq = floor;
            let mut hash = rh.clone();
            loop {
                let next = seq + 1;
                match records.get(&next) {
                    Some((prev, rh)) if prev == &hash => {
                        seq = next;
                        hash = rh.clone();
                    }
                    _ => break, // first hole OR link break → contiguous range ends
                }
            }
            (seq, hash)
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Agree,
    Pending,
    /// lone-peer conflict — bounded fork evidence, does NOT block.
    Suspect,
    /// DS-corroborated conflict — blocks.
    Fork,
}

/// coverage: seq -> (hash, ds_signed). The recipient's own verified head coverage.
/// The CON-009 comparison core: what does a peer attestation claiming (head_seq, head_hash) mean?
fn compare_attestation(coverage: &BTreeMap<i64, (String, bool)>, head_seq: i64, head_hash: &str) -> Verdict {
    match coverage.get(&head_seq) {
        None => Verdict::Pending, // missing local coverage is NOT disagreement
        Some((hash, ds_signed)) => {
            if hash == head_hash {
                Verdict::Agree
            } else if *ds_signed {
                // conflict against the recipient's OWN DS-signed record → blocking fork
                Verdict::Fork
            } else {
                // conflict, but the recipient's range is not DS-corroborated → suspect
                Verdict::Suspect
            }
        }
    }
}

fn rec(prev: &str, hash: &str) -> (String, String) {
    (prev.into(), hash.into())
}

/// contiguousHead walks an unbroken range and stops at the first link break.
#[test]
fn contiguous_head_stops_at_a_link_break() {
    let mut r = Records::new();
    r.insert(1, rec("H0", "h1"));
    r.insert(2, rec("h1", "h2"));
    r.insert(3, rec("WRONG", "h3")); // prev_hash does not link to h2
    let head = contiguous_head(1, "H0", &r);
    println!("[H9 attest] link break at 3 -> head {head:?}");
    assert_eq!(head, (2, "h2".into()));
}

/// A fully contiguous range yields its last record as the head.
#[test]
fn contiguous_head_reaches_the_end_of_a_contiguous_range() {
    let mut r = Records::new();
    r.insert(1, rec("H0", "h1"));
    r.insert(2, rec("h1", "h2"));
    r.insert(3, rec("h2", "h3"));
    assert_eq!(contiguous_head(1, "H0", &r), (3, "h3".into()));
    println!("[H9 attest] contiguous 1..3 -> head (3, h3)");
}

/// A hole immediately after the floor yields the floor itself; nothing at the floor yields floor-1.
#[test]
fn contiguous_head_handles_holes_and_empty() {
    let mut r = Records::new();
    r.insert(1, rec("H0", "h1"));
    r.insert(3, rec("h2", "h3")); // gap at 2
    assert_eq!(contiguous_head(1, "H0", &r), (1, "h1".into()));
    assert_eq!(contiguous_head(5, "Hfloor", &Records::new()), (4, "Hfloor".into()));
    println!("[H9 attest] hole@2 -> head (1,h1); empty@floor5 -> (4,Hfloor)");
}

/// An attestation the recipient cannot see is pending, not disagreement.
#[test]
fn out_of_coverage_attestation_is_pending() {
    let cov = BTreeMap::new();
    assert_eq!(compare_attestation(&cov, 9, "hx"), Verdict::Pending);
    println!("[H9 attest] no coverage -> Pending");
}

/// A matching head agrees.
#[test]
fn matching_head_agrees() {
    let mut cov = BTreeMap::new();
    cov.insert(4, ("h4".to_string(), true));
    assert_eq!(compare_attestation(&cov, 4, "h4"), Verdict::Agree);
    println!("[H9 attest] matching head -> Agree");
}

/// A lone-peer conflict is SUSPECT (non-blocking); a DS-corroborated conflict is a blocking FORK.
#[test]
fn conflict_is_suspect_or_fork_by_ds_corroboration() {
    let mut lone = BTreeMap::new();
    lone.insert(4, ("h4".to_string(), false)); // recipient's range NOT DS-signed
    assert_eq!(compare_attestation(&lone, 4, "h4-other"), Verdict::Suspect);

    let mut ds = BTreeMap::new();
    ds.insert(4, ("h4".to_string(), true)); // DS-corroborated
    assert_eq!(compare_attestation(&ds, 4, "h4-other"), Verdict::Fork);
    println!("[H9 attest] conflict: lone-peer -> Suspect ; DS-corroborated -> Fork (blocks)");
}
