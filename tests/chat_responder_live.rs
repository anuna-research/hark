//! Live two-agent responder test (SPEC-003 REQ-002/REQ-005).
//!
//! Two hark chat agents join the same channel, both advertising `cite`. A raw
//! "asker" connection publishes one `cite` ask. The claim round must elect
//! **exactly one** of the two agents to answer it — that agent's `recv` queue
//! gets the ask; the other's does not (within the liveness window).
//!
//! Liveness T is set high so the loser's fallback does not fire during the test
//! (the elected agent here is a passive test harness that never actually
//! replies, which would otherwise trigger the REQ-007 take-over). The fallback
//! logic itself is covered by `chat_responder` unit tests.
//!
//! Ignored by default — needs a hub at ws://localhost:8080/chat/v1
//! (`cd ../cbcl-chat && make shell`). Run with:
//!   cargo test --test chat_responder_live -- --ignored --nocapture

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use hark::chat::create_chat_agent;
use hark::chat_frame::decode_payload;
use hark::daemon::{AgentStore, AgentStoreConfig};
use hark::identity::ChatIdentity;
use hark::signed_transport::{SignedConn, parse_conn_bootstrap};
use tokio_tungstenite::{connect_async, tungstenite::Message as WsMessage};
use url::Url;

fn store(prefix: &str) -> AgentStore {
    AgentStore::new(AgentStoreConfig {
        agent_id_prefix: prefix.to_owned(),
        max_messages_per_handle: 64,
        max_bytes_per_handle: 65_536,
    })
}

#[tokio::test]
#[ignore = "requires a running cbcl-chat hub on ws://localhost:8080/chat/v1"]
async fn exactly_one_of_two_agents_is_elected() {
    let ws = Url::parse("ws://localhost:8080/chat/v1").expect("url");
    let window = Duration::from_millis(300);
    let liveness = Duration::from_secs(30); // keep the loser from falling back mid-test

    let store_a = store("resp-a");
    let store_b = store("resp-b");
    let (agent_a, _warnings_a) = create_chat_agent(
        store_a.clone(),
        &ws,
        "@general",
        "@resp-a",
        vec!["summarize".to_owned()],
        None,
        None, // added_by
        window,
        liveness,
        Arc::new(ChatIdentity::from_seed([11u8; 32])),
        None,
        false,
    )
    .await
    .expect("agent A joins");
    let (agent_b, _warnings_b) = create_chat_agent(
        store_b.clone(),
        &ws,
        "@general",
        "@resp-b",
        vec!["summarize".to_owned()],
        None,
        None, // added_by
        window,
        liveness,
        Arc::new(ChatIdentity::from_seed([12u8; 32])),
        None,
        false,
    )
    .await
    .expect("agent B joins");

    // A raw asker: bootstrap the signed-member wire (SPEC-012), join, then
    // publish one cite ask carrying a thread id. Frames are signed over the
    // domain-separated envelope via SignedConn — the production path; there is
    // no bare-payload signer (SPEC-013 OQ-001 / R4-06).
    let asker = ChatIdentity::from_seed([99u8; 32]);
    let (mut sock, _) = connect_async(ws.as_str()).await.expect("asker connects");
    let mut conn = recv_bootstrap(&mut sock).await;
    let hello = format!(
        "(hello @general :from @asker99 :key \"{}\")",
        asker.public_key_b64()
    );
    send_signed(&mut sock, &mut conn, &asker, &hello).await;
    // Let the hub enrol + ack the asker before the ask.
    tokio::time::sleep(Duration::from_millis(300)).await;
    // A lang-wrapped ask in the agents' learned dialect (SPEC-005): only the
    // `(lang …)` form triggers the responder; bare cite/poll are ignored.
    let ask = "(lang summarize (ask @general \"what is X?\" :from @asker99 :thread \"ask-xyz\"))";
    send_signed(&mut sock, &mut conn, &asker, ask).await;

    // After the Δ window both agents have ranked; exactly one holds the ask in
    // its recv queue. Poll each once with a window comfortably past Δ but well
    // under T.
    let a_got = store_a
        .recv(&agent_a, Some(Duration::from_millis(1500)))
        .await
        .ok();
    let b_got = store_b
        .recv(&agent_b, Some(Duration::from_millis(1500)))
        .await
        .ok();

    eprintln!("A recv: {a_got:?}");
    eprintln!("B recv: {b_got:?}");

    let a_has = a_got
        .as_deref()
        .map(|m| m.contains("ask-xyz"))
        .unwrap_or(false);
    let b_has = b_got
        .as_deref()
        .map(|m| m.contains("ask-xyz"))
        .unwrap_or(false);
    assert!(
        a_has ^ b_has,
        "exactly one agent must be elected to answer (A={a_has}, B={b_has})"
    );
}

type LiveSocket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Read the hub's first frame — the `(tell @client "conn-nonce" …)` bootstrap —
/// and prime a `SignedConn` from it, as `create_chat_agent` does internally.
async fn recv_bootstrap(sock: &mut LiveSocket) -> SignedConn {
    let msg = tokio::time::timeout(Duration::from_secs(5), sock.next())
        .await
        .expect("bootstrap within 5s")
        .expect("socket open")
        .expect("bootstrap frame");
    let text = match &msg {
        WsMessage::Binary(bytes) => {
            String::from_utf8_lossy(decode_payload(bytes).expect("well-formed frame")).into_owned()
        }
        WsMessage::Text(text) => text.to_string(),
        other => panic!("unexpected first frame (expected conn-nonce bootstrap): {other:?}"),
    };
    let boot = parse_conn_bootstrap(&text).expect("first frame is the conn-nonce bootstrap");
    SignedConn::from_bootstrap(&boot)
}

async fn send_signed(
    sock: &mut LiveSocket,
    conn: &mut SignedConn,
    identity: &ChatIdentity,
    text: &str,
) {
    let frame = conn.sign_chat_frame(identity, text.as_bytes());
    sock.send(WsMessage::Binary(frame.into()))
        .await
        .expect("send frame");
}
