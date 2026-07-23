//! CON-009 — log-head attestation (H9). `contiguousHead` + the suspect-vs-fork comparison.
//! Ports the pure decision logic of `mls-ds-attestation.mjs`; the byte recogniser + sig
//! verification are consumed from cbcl-rs (F-07).

use std::collections::BTreeMap;

/// records: seq -> (prev_hash, record_hash). A verified DS-signed contiguous range.
pub type Records = BTreeMap<i64, (String, String)>;

/// contiguousHead (REQ-065): from the signed floor checkpoint, the last (seq, hash) reachable
/// by an unbroken chain.
pub fn contiguous_head(floor: i64, floor_prev: &str, records: &Records) -> (i64, String) {
    match records.get(&floor) {
        None => (floor - 1, floor_prev.to_string()),
        Some((prev, _)) if prev != floor_prev => (floor - 1, floor_prev.to_string()),
        Some((_, rh)) => {
            let (mut seq, mut hash) = (floor, rh.clone());
            loop {
                let next = seq + 1;
                match records.get(&next) {
                    Some((prev, rh)) if prev == &hash => {
                        seq = next;
                        hash = rh.clone();
                    }
                    _ => break,
                }
            }
            (seq, hash)
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Agree,
    Pending,
    Suspect, // lone-peer conflict, non-blocking
    Fork,    // DS-corroborated conflict, blocks
}

/// coverage: seq -> (hash, ds_signed). The CON-009 comparison of a peer attestation claim.
pub fn compare_attestation(coverage: &BTreeMap<i64, (String, bool)>, head_seq: i64, head_hash: &str) -> Verdict {
    match coverage.get(&head_seq) {
        None => Verdict::Pending,
        Some((hash, ds_signed)) => {
            if hash == head_hash {
                Verdict::Agree
            } else if *ds_signed {
                Verdict::Fork
            } else {
                Verdict::Suspect
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn head_walk_and_suspect_vs_fork() {
        let mut r = Records::new();
        r.insert(1, ("H0".into(), "h1".into()));
        r.insert(2, ("h1".into(), "h2".into()));
        r.insert(3, ("WRONG".into(), "h3".into()));
        assert_eq!(contiguous_head(1, "H0", &r), (2, "h2".into()));

        let mut lone = BTreeMap::new();
        lone.insert(4, ("h4".to_string(), false));
        assert_eq!(compare_attestation(&lone, 4, "h4-other"), Verdict::Suspect);
        let mut ds = BTreeMap::new();
        ds.insert(4, ("h4".to_string(), true));
        assert_eq!(compare_attestation(&ds, 4, "h4-other"), Verdict::Fork);
        assert_eq!(compare_attestation(&ds, 9, "x"), Verdict::Pending);
    }
}
