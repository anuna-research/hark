//! End-to-end `hark pair` client transport test (SPEC-016 REQ-007). A mock
//! `/pair/v1` server replays the committed known-answer vectors: it asserts the
//! client sends the fixture's msg_a + mac_a (proving the client crypto, already
//! vector-tested) and replays the fixture's pair_resp / pair_release. The
//! client must then decode the frames, authenticate the hub via mac_b, and
//! decrypt the record — exercising the whole WS transport + orchestration
//! deterministically, without duplicating the responder crypto.

use std::net::SocketAddr;

use futures_util::{SinkExt, StreamExt};
use hark::pairing::{PairingCode, client};
use serde_json::Value;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

fn load() -> Value {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/pairing-vectors.json"
    ))
    .unwrap();
    serde_json::from_str(&raw).unwrap()
}

fn b64(hex: &str) -> String {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    B64.encode(bytes)
}

/// A mock pairing hub that drives one handshake from the fixture.
async fn mock_pair_hub(v: Value) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let out = v["outputs"].clone();
    let inp = v["inputs"].clone();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();

        // Frame 1: pair_init — assert the client sent the fixture msg_a + id.
        let init: Value = match ws.next().await.unwrap().unwrap() {
            Message::Text(t) => serde_json::from_str(&t).unwrap(),
            other => panic!("expected text pair_init, got {other:?}"),
        };
        assert_eq!(init["type"], "pair_init");
        assert_eq!(init["pairing_id"], inp["pairing_id"]);
        assert_eq!(init["msg_a"], b64(out["msg_a_hex"].as_str().unwrap()));

        // Frame 2: replay pair_resp.
        ws.send(Message::Text(
            serde_json::json!({"type":"pair_resp","msg_b": b64(out["msg_b_hex"].as_str().unwrap())})
                .to_string()
                .into(),
        ))
        .await
        .unwrap();

        // Frame 3: pair_confirm — assert the client sent the fixture mac_a.
        let confirm: Value = match ws.next().await.unwrap().unwrap() {
            Message::Text(t) => serde_json::from_str(&t).unwrap(),
            other => panic!("expected text pair_confirm, got {other:?}"),
        };
        assert_eq!(confirm["type"], "pair_confirm");
        assert_eq!(confirm["mac_a"], b64(out["mac_a_hex"].as_str().unwrap()));

        // Frame 4: replay pair_release (mac_b + ciphertext).
        ws.send(Message::Text(
            serde_json::json!({
                "type": "pair_release",
                "mac_b": b64(out["mac_b_hex"].as_str().unwrap()),
                "ciphertext": b64(out["ciphertext_hex"].as_str().unwrap()),
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
        let _ = ws.close(None).await;
    });
    addr
}

#[tokio::test]
async fn pair_client_completes_handshake_and_returns_record() {
    let v = load();
    let inp = v["inputs"].clone();
    let ephemeral: [u8; 64] = {
        let hex = inp["agent_ephemeral_hex"].as_str().unwrap();
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        bytes.try_into().unwrap()
    };
    let words: Vec<String> = inp["phrase"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w.as_str().unwrap().to_string())
        .collect();
    let code = PairingCode {
        pairing_id: inp["pairing_id"].as_str().unwrap().to_string(),
        words,
    };

    let addr = mock_pair_hub(v).await;
    let url = url::Url::parse(&format!("ws://{addr}/pair/v1")).unwrap();

    let record = client::run_pairing_with_ephemeral(&url, &code, &ephemeral)
        .await
        .expect("pairing completes");

    assert_eq!(record.agent_name, "@aria");
    assert_eq!(record.channel, "@research");
    assert!(record.enc);
    assert!(record.has_cap());
    assert_eq!(record.adder, "@mira");
    assert_eq!(record.dialects.len(), 1);
    assert_eq!(record.dialects[0].name, "cite");
}

#[tokio::test]
async fn pair_client_surfaces_hub_error() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        let _ = ws.next().await; // consume pair_init
        ws.send(Message::Text(
            serde_json::json!({"type":"error","code":"UNKNOWN_PAIRING","message":"unknown_pairing_id"})
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
        let _ = ws.close(None).await;
    });

    let code = PairingCode {
        pairing_id: "deadbeef".to_string(),
        words: vec![
            "account".into(),
            "clinic".into(),
            "text".into(),
            "wheel".into(),
        ],
    };
    let url = url::Url::parse(&format!("ws://{addr}/pair/v1")).unwrap();
    let err = client::run_pairing(&url, &code).await.unwrap_err();
    assert!(
        matches!(err, client::PairClientError::HubError { ref code, .. } if code == "UNKNOWN_PAIRING"),
        "got {err:?}"
    );
}
