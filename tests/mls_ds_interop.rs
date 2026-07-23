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
