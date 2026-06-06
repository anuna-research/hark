//! Live end-to-end validation of the SPEC-012 signed-member router handshake
//! (slice-6). Gated on `CBCL_ROUTER_WS` — skipped unless it points at a running
//! router hub (e.g. `ws://localhost:18080/agent/v1`). Proves the 6b signing core
//! interoperates with the real LFE hub: receive the conn-nonce bootstrap, send a
//! signed hello, then a signed `(meta (query (list)))`, and confirm the hub
//! accepts both (a reply comes back, not a `bad-signature` error).

use ed25519_dalek::{Signer, SigningKey};
use futures_util::{SinkExt, StreamExt};
use hark::chat_frame::FrameSigner;
use hark::signed_transport::{SignedConn, build_router_hello, parse_conn_bootstrap};
use std::time::Duration;
use tokio_tungstenite::{connect_async, tungstenite::Message as WsMessage};

/// A FrameSigner backed by ed25519-dalek (the agent's identity key).
struct Key(SigningKey);
impl FrameSigner for Key {
    fn sign(&self, payload: &[u8]) -> [u8; 64] {
        self.0.sign(payload).to_bytes()
    }
}

fn frame_text(msg: WsMessage) -> Option<String> {
    match msg {
        WsMessage::Binary(b) => Some(String::from_utf8_lossy(&b).into_owned()),
        WsMessage::Text(t) => Some(t.to_string()),
        _ => None,
    }
}

async fn next_text(ws: &mut (impl StreamExt<Item = Result<WsMessage, tokio_tungstenite::tungstenite::Error>> + Unpin)) -> Option<String> {
    let m = tokio::time::timeout(Duration::from_secs(3), ws.next()).await.ok()??.ok()?;
    frame_text(m)
}

#[tokio::test]
async fn signed_hello_and_query_accepted_by_live_router() {
    let Ok(url) = std::env::var("CBCL_ROUTER_WS") else {
        eprintln!("skip: CBCL_ROUTER_WS unset");
        return;
    };

    let (mut ws, _) = connect_async(&url).await.expect("connect to router");

    // 1. the hub's first frame is the conn-nonce bootstrap.
    let boot_text = next_text(&mut ws).await.expect("bootstrap frame");
    let boot = parse_conn_bootstrap(&boot_text)
        .unwrap_or_else(|| panic!("not a conn-nonce bootstrap: {boot_text}"));

    // 2. our signing identity + per-connection signer.
    let key = Key(SigningKey::from_bytes(&[3u8; 32]));
    let pub_b64 = {
        use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
        B64.encode(SigningKey::from_bytes(&[3u8; 32]).verifying_key().to_bytes())
    };
    let mut conn = SignedConn::from_bootstrap(&boot);

    // 3. signed hello — if the signature/envelope were wrong, the hub replies
    //    with a `(... (error @router "bad-signature"))` frame.
    let hello = build_router_hello("hark-live-test", &pub_b64, &["demo".to_string()]);
    let hello_frame = conn.sign_router_frame(&key, hello.as_bytes());
    ws.send(WsMessage::Binary(hello_frame.into())).await.expect("send hello");

    // 4. a signed meta-query — the router replies with the dialect list. Getting
    //    a non-error reply proves the signed hello was accepted AND a subsequent
    //    signed frame verified + was routed end-to-end.
    let query = b"(meta (query (list)))";
    let query_frame = conn.sign_router_frame(&key, query);
    ws.send(WsMessage::Binary(query_frame.into())).await.expect("send query");

    // 5. drain a few frames; assert we never see a bad-signature error and that
    //    the connection is accepted (a reply / dialect list, or at least no
    //    auth error before the read window closes).
    let mut saw_reply = false;
    for _ in 0..4 {
        let Some(t) = next_text(&mut ws).await else { break };
        assert!(
            !t.contains("bad-signature") && !t.contains("malformed"),
            "hub rejected a signed frame: {t}"
        );
        if t.contains("(reply") || t.contains("dialect") || t.contains("(meta") {
            saw_reply = true;
        }
    }
    assert!(saw_reply, "expected a reply to the signed meta-query from the live hub");
}
