//! IMPL-025 — the client pull loop RUNNING end-to-end against a DS (TEST-025, client half).
//!
//! Drives hark's real `PullDriver` against a minimal in-test Delivery Service that signs a record
//! chain with a DS key, exercising the full client loop: `next-record` pull → verify under the
//! **pinned DS key** → reduce (exact-next) → advance the cursor, over a real signed chain. This is
//! the "pull loop running" the spec's acceptance calls for, in isolation.
//!
//! The FULL TEST-025 (a real browser + a real hark daemon + the production SPEC-024 hub) is the
//! two-repo coordinated release: the browser and the hub-as-DS live in cbcl-bus (IMPL-024 W5–W10).
//! This proves the hark end runs correctly against a conforming DS.
//!
//!   cargo test --test mls_ds_interop -- --nocapture

use cbcl_core::mls_ds::{DomainTuple, Ed25519Keypair};
use cbcl_core::sexpr::{Atom, SExpr};
use hark::mls_ds::pull::{PullAction, PullDriver};
use hark::mls_ds::{record_hash, ClientLog, RecordResponse, Verdict};

const H0: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

fn log_record(seq: i64, prev: &str) -> SExpr {
    SExpr::List(vec![
        SExpr::Atom(Atom::Symbol("log-v1".into())),
        SExpr::Atom(Atom::Str("room-alpha".into())),
        SExpr::Atom(Atom::Num(seq)),
        SExpr::Atom(Atom::Str(prev.into())),
    ])
}

/// A minimal Delivery Service: a DS key + a signed, hash-linked record chain, served by pull.
struct MockDs {
    ds: Ed25519Keypair,
    chain: Vec<RecordResponse>,
}

impl MockDs {
    fn new(seed: [u8; 8], len: i64, genesis_hash: &str) -> Self {
        let mut full = [0u8; 32];
        full[..8].copy_from_slice(&seed);
        let ds = Ed25519Keypair::from_seed(&full);
        let mut chain = Vec::new();
        let mut prev = genesis_hash.to_string();
        for seq in 1..=len {
            let rec = log_record(seq, &prev);
            let rh = record_hash(&rec);
            let sig = DomainTuple::Record { log_record: rec.clone() }.sign(&ds);
            chain.push(RecordResponse {
                seq,
                prev_hash: prev.clone(),
                record_hash: rh.clone(),
                record_signature: sig,
                log_record: rec,
            });
            prev = rh;
        }
        Self { ds, chain }
    }

    /// `next-record(after_seq)`: serve the record at `after_seq + 1`, or None at head.
    fn next_record(&self, after_seq: i64) -> Option<&RecordResponse> {
        self.chain.get(after_seq as usize)
    }

    fn ds_key(&self) -> [u8; 32] {
        self.ds.public_bytes()
    }
}

/// The honest end-to-end: the client pulls the whole chain, verifying + reducing each record.
#[test]
fn client_pull_loop_runs_end_to_end_against_a_ds() {
    let ds = MockDs::new(*b"ds-key01", 3, H0);
    let ds_vk = ds.ds_key();
    let mut driver = PullDriver::new(ClientLog { cursor: 0, cursor_hash: H0.into() });

    for expected in 1..=3 {
        match driver.next_pull() {
            PullAction::Pull { after_seq } => {
                let resp = ds.next_record(after_seq).expect("DS serves the next record");
                let verdict = driver.on_record(&ds_vk, resp);
                println!("[interop] pulled after_seq={after_seq} -> {verdict:?}");
                assert!(
                    matches!(verdict, Verdict::Applied { cursor, .. } if cursor == expected),
                    "record {expected} must C-APPLY, got {verdict:?}"
                );
            }
            other => panic!("expected a Pull, got {other:?}"),
        }
    }
    assert_eq!(driver.cursor().cursor, 3, "client pulled + verified + reduced the whole chain");
    println!("[interop] client advanced cursor 0 -> 3 over the DS's signed chain");
}

/// A record signed by a NON-pinned key is rejected — the DS trust boundary holds under load.
#[test]
fn client_rejects_records_not_signed_by_the_pinned_ds() {
    let ds = MockDs::new(*b"ds-key01", 1, H0);
    let forger = MockDs::new(*b"forger00", 1, H0); // a different key, same chain shape
    let mut driver = PullDriver::new(ClientLog { cursor: 0, cursor_hash: H0.into() });

    // The forger's record is well-formed but signed by the wrong key.
    let PullAction::Pull { after_seq } = driver.next_pull() else { panic!("expected Pull") };
    let forged = forger.next_record(after_seq).expect("forger serves a record");
    let verdict = driver.on_record(&ds.ds_key(), forged); // verify under the PINNED (real) DS key
    println!("[interop] forged record under pinned key -> {verdict:?}");
    assert!(matches!(verdict, Verdict::Violation(_)), "a non-DS-signed record must be ds-equivocation");
    assert_eq!(driver.cursor().cursor, 0, "cursor held — no advance on a rejected record");
}

// ── the CROSS-RUNTIME deliver honest-path ────────────────────────────────────────
// hark's real PullDriver consumes a signed, hash-linked record CHAIN produced by the
// REAL cbcl-bus LFE hub (cbcl-mls-ds-sign, enacl/libsodium), emitted to
// tests/fixtures/ds_sign_chain.txt. The client pulls each record, verifies it under
// the hub's pinned key, reduces (exact-next), and advances — end-to-end, no MockDs.

fn hx<const N: usize>(s: &str) -> [u8; N] {
    let v: Vec<u8> = (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect();
    let mut a = [0u8; N];
    a.copy_from_slice(&v);
    a
}

#[test]
fn client_pull_loop_consumes_lfe_hub_chain() {
    let raw = include_str!("fixtures/ds_sign_chain.txt");
    let mut ds_pubkey = [0u8; 32];
    let mut h0 = String::new();
    let mut recs: Vec<(i64, String, String, [u8; 64])> = vec![];
    for line in raw.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let (k, v) = line.split_once(' ').unwrap();
        match k {
            "ds_pubkey_hex" => ds_pubkey = hx::<32>(v.trim()),
            "h0" => h0 = v.trim().to_string(),
            "rec" => {
                let f: Vec<&str> = v.split_whitespace().collect();
                recs.push((f[0].parse().unwrap(), f[1].to_string(), f[2].to_string(), hx::<64>(f[3])));
            }
            _ => {}
        }
    }
    assert_eq!(recs.len(), 3, "the LFE hub emitted a 3-record chain");

    // the honest-path deliver: pull -> verify (pinned key) -> reduce -> advance, over the WHOLE chain.
    let mut driver = PullDriver::new(ClientLog { cursor: 0, cursor_hash: h0.clone() });
    for (i, (seq, prev, rh, sig)) in recs.iter().enumerate() {
        let expected = (i as i64) + 1;
        let PullAction::Pull { after_seq } = driver.next_pull() else {
            panic!("expected a Pull at cursor {i}")
        };
        assert_eq!(after_seq, i as i64, "pull requests the record after the cursor");
        let resp = RecordResponse {
            seq: *seq,
            prev_hash: prev.clone(),
            record_hash: rh.clone(),
            record_signature: *sig,
            log_record: log_record(*seq, prev),
        };
        let verdict = driver.on_record(&ds_pubkey, &resp);
        println!("[interop] LFE-hub rec {expected} -> {verdict:?}");
        assert!(
            matches!(verdict, Verdict::Applied { cursor, .. } if cursor == expected),
            "the LFE hub's record {expected} must C-APPLY in hark, got {verdict:?}"
        );
    }
    assert_eq!(driver.cursor().cursor, 3, "hark pulled+verified+reduced the LFE hub's whole signed chain");
    println!("[interop] hark client advanced cursor 0 -> 3 over the REAL cbcl-bus hub's DS-signed chain");

    // NI — a record with a forged signature is rejected under the same pinned key.
    let mut d2 = PullDriver::new(ClientLog { cursor: 0, cursor_hash: h0 });
    let PullAction::Pull { .. } = d2.next_pull() else { panic!() };
    let (seq, prev, rh, _) = &recs[0];
    let forged = RecordResponse {
        seq: *seq,
        prev_hash: prev.clone(),
        record_hash: rh.clone(),
        record_signature: [0u8; 64],
        log_record: log_record(*seq, prev),
    };
    assert!(matches!(d2.on_record(&ds_pubkey, &forged), Verdict::Violation(_)), "forged sig -> ds-equivocation");
    assert_eq!(d2.cursor().cursor, 0, "cursor held on the forged record");
}
