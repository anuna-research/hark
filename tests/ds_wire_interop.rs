//! TEST-025 — the PRODUCTION CBCL-dialect DS wire, cross-runtime.
//!
//! Consumes `tests/fixtures/ds_cbcl_wire_vectors.txt`, emitted by the LFE hub's REAL
//! `/mls-ds/v1` handler (`cbcl-mls-ds-interop-tests:emit_cbcl_wire_vectors_test` in
//! cbcl-bus): literal request/response wire frames from a genesis-register +
//! payload-carrying commit-submit + next-record/genesis-get exchange.
//!
//! What acceptance PROVES, per step:
//! - `DsWire::inbound` accepting the hub's response proves the CON-012 `:caused-by`
//!   binding agrees BYTE-FOR-BYTE across runtimes: hark hashes ITS OWN constructed
//!   request (canonical bytes of the parsed algebra); the hub hashed ITS parse of the
//!   same logical frame. One byte of divergence in parser, algebra, or canonical
//!   encoder and the response is rejected as a transplant.
//! - `PullDriver::on_record` reaching `Applied` proves record-hash parity AND the DS
//!   signature (`DomainTuple::Record` over the payload-carrying log-record) verifies
//!   under the fixture-pinned hub key — the delivered payload bytes are covered.
//! - `record_payload` recovering the submitted frame proves the end-to-end payload
//!   path: submit → signed record → pull → extract.

use std::collections::HashMap;

use hark::mls_ds::pull::{PullAction, PullDriver};
use hark::mls_ds::task::record_payload;
use hark::mls_ds::wire::{pk32, DsInbound, DsWire};
use hark::mls_ds::{ClientLog, Verdict};

const H0: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

fn fixture() -> HashMap<String, String> {
    let raw = include_str!("fixtures/ds_cbcl_wire_vectors.txt");
    raw.lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .filter_map(|l| l.split_once(' '))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[test]
fn genesis_get_binds_and_pins_anchor_plus_ds_key() {
    let v = fixture();
    let mut w = DsWire::new("room-alpha");
    let req = w.genesis_get_request().expect("request recognised");
    // Cross-runtime render parity: hark's own request text IS the hub's fixture text.
    assert_eq!(req, v["genesis_request"], "request render parity (Display vs LFE render)");
    // Accepting the hub's response proves the :caused-by content-hash parity (CON-012).
    match w.inbound(&v["genesis_response"]).expect("hub response binds hark's request hash") {
        DsInbound::GenesisAnchor { anchor, ds_vk } => {
            assert_eq!(anchor, v["anchor"]);
            assert_eq!(ds_vk, pk32(&v["ds_pubkey_hex"]).unwrap());
        }
        other => panic!("expected GenesisAnchor, got {other:?}"),
    }
}

#[test]
fn hub_record_admits_through_the_real_driver_and_yields_the_payload() {
    let v = fixture();
    let ds_vk = pk32(&v["ds_pubkey_hex"]).unwrap();

    let mut w = DsWire::new("room-alpha");
    let req = w.next_record_request(0).expect("request recognised");
    assert_eq!(req, v["pull_request"], "request render parity (Display vs LFE render)");

    // CON-011 recognition + CON-012 hash binding of the REAL hub response.
    let resp = match w.inbound(&v["pull_response"]).expect("hub response binds + recognises") {
        DsInbound::Record(resp) => resp,
        other => panic!("expected Record, got {other:?}"),
    };

    // CON-005 admission through the REAL driver: anchor + hash + hub DS-sig + exact-next.
    let mut driver =
        PullDriver::new(ClientLog { cursor: 0, cursor_hash: H0.into() }, Some(v["anchor"].clone()));
    assert_eq!(driver.next_pull(), PullAction::Pull { after_seq: 0 });
    let verdict = driver.on_record(&ds_vk, &resp);
    let Verdict::Applied { cursor, .. } = verdict else {
        panic!("hub record must C-APPLY, got {verdict:?}");
    };
    assert_eq!(cursor, 1);

    // The submitted payload rides the SIGNED record and comes back out.
    assert_eq!(record_payload(&resp.log_record).as_deref(), Some("payload-frame-1"));
}

#[test]
fn a_forged_hub_record_is_rejected_by_the_pinned_key() {
    let v = fixture();
    let mut w = DsWire::new("room-alpha");
    w.next_record_request(0).unwrap();
    let resp = match w.inbound(&v["pull_response"]).unwrap() {
        DsInbound::Record(resp) => resp,
        other => panic!("expected Record, got {other:?}"),
    };
    // A different pinned key (ds-key substitution) must reject the same record.
    let wrong = [7u8; 32];
    let mut driver =
        PullDriver::new(ClientLog { cursor: 0, cursor_hash: H0.into() }, Some(v["anchor"].clone()));
    driver.next_pull();
    assert_eq!(
        driver.on_record(&wrong, &resp),
        Verdict::Violation("ds-equivocation:record-signature-invalid")
    );
}

/// THE LIVE CAPSTONE — the REAL daemon pull task (`spawn_ds_pull_loop`: TOFU
/// genesis pinning, CBCL wire, PullDriver admission, DsApply hand-off) against a
/// LIVE cbcl-bus hub over a real WebSocket. Env-gated: set MLS_DS_URL
/// (ws://host:port/mls-ds/v1) — `apps/cbcl_chat/test/e2e/run-mls-ds.sh` drives it.
#[tokio::test]
async fn ds_pull_task_against_live_hub() {
    use futures_util::{SinkExt, StreamExt};
    use hark::mls_ds::task::{spawn_ds_pull_loop, DsPullConfig};
    use tokio_tungstenite::{connect_async, tungstenite::Message};

    let Ok(url) = std::env::var("MLS_DS_URL") else {
        eprintln!("skipped: set MLS_DS_URL to run against a live hub");
        return;
    };
    // A fresh room per run — the hub log is durable across runs.
    let room = format!("room-live-{}", std::process::id());

    // Another client (the submitter) seeds the log over the same CBCL wire.
    let (mut ws, _) = connect_async(&url).await.expect("hub reachable");
    let submits = [
        format!("(genesis-register (register-genesis \"{room}\") :caused-by \"begin\")"),
        format!("(commit-submit (submit \"{room}\" 0 \"live-payload-1\") :caused-by \"begin\")"),
        format!("(commit-submit (submit \"{room}\" 1 \"live-payload-2\") :caused-by \"begin\")"),
    ];
    for frame in submits {
        ws.send(Message::text(frame)).await.unwrap();
        let _ = ws.next().await.unwrap().unwrap(); // consume the ack
    }

    // The REAL daemon pull task: no pins on disk → genesis-get → TOFU-pin →
    // pull 0→2, each admitted record handed off as a DsApply.
    let dir = std::env::temp_dir().join(format!("hark-ds-live-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    spawn_ds_pull_loop(
        DsPullConfig {
            ds_url: url,
            room: room.clone(),
            state_dir: dir.clone(),
            poll: std::time::Duration::from_millis(200),
            initial_log: ClientLog { cursor: 0, cursor_hash: H0.into() },
        },
        tx,
    );

    let deadline = std::time::Duration::from_secs(10);
    let one = tokio::time::timeout(deadline, rx.recv()).await.expect("apply 1 in time").unwrap();
    assert_eq!(one.log.cursor, 1);
    assert_eq!(one.payload, "live-payload-1");
    let two = tokio::time::timeout(deadline, rx.recv()).await.expect("apply 2 in time").unwrap();
    assert_eq!(two.log.cursor, 2);
    assert_eq!(two.payload, "live-payload-2");

    // The TOFU pins landed on disk (anchor + DS key) — the reconnect posture.
    assert!(dir.join("anchor").exists() && dir.join("ds.pk").exists());
    let _ = std::fs::remove_dir_all(&dir);
    println!("[live] REAL pull task: genesis TOFU-pinned, cursor 0->2, payloads delivered");
}
