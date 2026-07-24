//! TEST-025 honest-path OVER A REAL SOCKET — hark's real `PullDriver` runs the pull
//! loop over a genuine localhost WebSocket (tokio-tungstenite, server + client)
//! against a Delivery Service. The DS signs records with cbcl-core
//! `DomainTuple::Record` — byte-identical to the cbcl-bus LFE hub
//! (`cbcl-mls-ds-sign`), proven by `parity_harness` oracle 2b — so this exercises
//! the transport end of the two-machine test: pull frame out over the wire, verify
//! the DS-signed record under the pinned key, reduce (exact-next), advance the
//! cursor, request the next. A forged record over the same socket is rejected.
//!
//!   cargo test --test ds_socket_interop -- --nocapture

use cbcl_core::mls_ds::{DomainTuple, Ed25519Keypair};
use cbcl_core::sexpr::{Atom, SExpr};
use futures_util::{SinkExt, StreamExt};
use hark::mls_ds::pull::{PullAction, PullDriver};
use hark::mls_ds::{record_hash, ClientLog, RecordResponse, Verdict};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

const H0: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

fn sym(s: &str) -> SExpr {
    SExpr::Atom(Atom::Symbol(s.into()))
}
fn st(s: &str) -> SExpr {
    SExpr::Atom(Atom::Str(s.into()))
}
fn num(n: i64) -> SExpr {
    SExpr::Atom(Atom::Num(n))
}
fn log_record(seq: i64, prev: &str) -> SExpr {
    SExpr::List(vec![sym("log-v1"), st("room-alpha"), num(seq), st(prev)])
}
fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn from_hex_64(s: &str) -> [u8; 64] {
    let v: Vec<u8> = (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect();
    let mut a = [0u8; 64];
    a.copy_from_slice(&v);
    a
}

struct Rec {
    seq: i64,
    prev: String,
    rh: String,
    sig: [u8; 64],
}

fn build_chain(ds: &Ed25519Keypair, n: i64) -> Vec<Rec> {
    let mut out = vec![];
    let mut prev = H0.to_string();
    for seq in 1..=n {
        let rec = log_record(seq, &prev);
        let rh = record_hash(&rec);
        let sig = DomainTuple::Record { log_record: rec }.sign(ds);
        out.push(Rec { seq, prev: prev.clone(), rh: rh.clone(), sig });
        prev = rh;
    }
    out
}

/// Spawn a DS on a real localhost WebSocket serving `next-record <cursor>` from `served`.
/// Returns the bound address.
async fn spawn_ds(served: Vec<String>) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        while let Some(Ok(msg)) = ws.next().await {
            if let Message::Text(req) = msg {
                if let Some(c) = req.as_str().strip_prefix("next-record ") {
                    let cursor: usize = c.trim().parse().unwrap();
                    let reply = served.get(cursor).cloned().unwrap_or_else(|| "at-head".into());
                    ws.send(Message::text(reply)).await.unwrap();
                }
            }
        }
    });
    addr
}

fn parse_record(frame: &str) -> RecordResponse {
    let f: Vec<&str> = frame.split('|').collect(); // seq|prev|record_hash|sig_hex
    let seq: i64 = f[0].parse().unwrap();
    RecordResponse {
        seq,
        prev_hash: f[1].to_string(),
        record_hash: f[2].to_string(),
        record_signature: from_hex_64(f[3]),
        log_record: log_record(seq, f[1]),
    }
}

#[tokio::test]
async fn hark_pull_loop_over_a_real_websocket() {
    let ds = Ed25519Keypair::from_seed(&[42u8; 32]);
    let ds_vk = ds.public_bytes();
    let chain = build_chain(&ds, 3);
    let served: Vec<String> =
        chain.iter().map(|r| format!("{}|{}|{}|{}", r.seq, r.prev, r.rh, to_hex(&r.sig))).collect();
    let addr = spawn_ds(served).await;

    // hark client: the REAL PullDriver, driven over a REAL WebSocket.
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/mls-ds/v1")).await.unwrap();
    let mut driver = PullDriver::new(ClientLog { cursor: 0, cursor_hash: H0.into() });
    for expected in 1..=3 {
        let PullAction::Pull { after_seq } = driver.next_pull() else { panic!("expected a Pull") };
        ws.send(Message::text(format!("next-record {after_seq}"))).await.unwrap();
        let Message::Text(resp) = ws.next().await.unwrap().unwrap() else { panic!("expected a record frame") };
        let verdict = driver.on_record(&ds_vk, &parse_record(resp.as_str()));
        println!("[socket] pulled after_seq={after_seq} -> {verdict:?}");
        assert!(
            matches!(verdict, Verdict::Applied { cursor, .. } if cursor == expected),
            "record {expected} must C-APPLY over the socket, got {verdict:?}"
        );
    }
    assert_eq!(driver.cursor().cursor, 3, "hark ran the pull loop over a real WebSocket (cursor 0->3)");
    println!("[socket] hark PullDriver advanced 0->3 over a real WebSocket against a DS");
}

#[tokio::test]
async fn hark_rejects_a_forged_record_over_the_socket() {
    let ds = Ed25519Keypair::from_seed(&[42u8; 32]);
    let ds_vk = ds.public_bytes();
    // a well-formed chain, but the served signature is zeroed (a non-DS signer).
    let chain = build_chain(&ds, 1);
    let served: Vec<String> =
        chain.iter().map(|r| format!("{}|{}|{}|{}", r.seq, r.prev, r.rh, to_hex(&[0u8; 64]))).collect();
    let addr = spawn_ds(served).await;

    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/mls-ds/v1")).await.unwrap();
    let mut driver = PullDriver::new(ClientLog { cursor: 0, cursor_hash: H0.into() });
    let PullAction::Pull { after_seq } = driver.next_pull() else { panic!() };
    ws.send(Message::text(format!("next-record {after_seq}"))).await.unwrap();
    let Message::Text(resp) = ws.next().await.unwrap().unwrap() else { panic!() };
    let verdict = driver.on_record(&ds_vk, &parse_record(resp.as_str()));
    assert!(matches!(verdict, Verdict::Violation(_)), "a forged record over the socket is ds-equivocation");
    assert_eq!(driver.cursor().cursor, 0, "cursor held over the socket on a rejected record");
}
