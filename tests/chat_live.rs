//! Live interop test for the cbcl-chat transport (IMPL-003 §6).
//!
//! Proves the hard part: a hark agent's Ed25519-signed `hello` over verbatim
//! CBCL bytes is accepted by a *real* running cbcl-chat hub — i.e. hark's
//! `ed25519-dalek` signature interoperates with the hub's libsodium
//! `verify-sender` (SPEC-001 CON-006). Acceptance is now proven by
//! `create_chat_agent` returning `Ok`: it blocks on the hub's join handshake
//! (`roomcfg` on accept, `(error … "slug")` on reject) before returning, so a
//! signature failure would surface as `ChatError::JoinRejected("bad-signature")`
//! rather than a silently half-joined handle.
//!
//! Ignored by default — it needs a hub at ws://localhost:8080/chat/v1
//! (`cd ../cbcl-chat && make shell`). Run with:
//!   cargo test --test chat_live -- --ignored --nocapture

use std::sync::Arc;
use std::time::Duration;

use hark::chat::{ChatError, create_chat_agent};
use hark::daemon::{AgentStore, AgentStoreConfig};
use hark::identity::ChatIdentity;
use url::Url;

fn store() -> AgentStore {
    AgentStore::new(AgentStoreConfig {
        agent_id_prefix: "hark-chat-test".to_owned(),
        max_messages_per_handle: 64,
        max_bytes_per_handle: 65_536,
    })
}

#[tokio::test]
#[ignore = "requires a running cbcl-chat hub on ws://localhost:8080/chat/v1"]
async fn signed_hello_is_accepted_by_live_hub() {
    let store = store();
    let identity = Arc::new(ChatIdentity::from_seed([42u8; 32]));
    let ws_url = Url::parse("ws://localhost:8080/chat/v1").expect("valid url");

    // A successful return is the assertion: create_chat_agent only returns Ok
    // after the hub acknowledged the join with a roomcfg frame, which it does
    // only once it has verified the Ed25519 signature against the :key. A broken
    // signature would come back as ChatError::JoinRejected("bad-signature").
    let handle = create_chat_agent(
        store.clone(),
        &ws_url,
        "@general",
        "@hark-test",
        vec!["cite".to_owned()],
        identity,
    )
    .await
    .expect("signed hello accepted + join acknowledged by live hub");

    // Backfill / presence frames flow through the receive loop after the ack;
    // draining one shows the connection is live, but acceptance is already proven.
    if let Ok(frame) = store.recv(&handle, Some(Duration::from_millis(800))).await {
        eprintln!("hub → agent (post-join): {frame}");
    }
}

#[tokio::test]
#[ignore = "requires a running cbcl-chat hub on ws://localhost:8080/chat/v1"]
async fn join_to_unknown_channel_is_rejected() {
    let store = store();
    let identity = Arc::new(ChatIdentity::from_seed([43u8; 32]));
    let ws_url = Url::parse("ws://localhost:8080/chat/v1").expect("valid url");

    // Entering a channel that does not exist (no :create intent) must be rejected
    // by the hub with `(error @… "no-such-channel")`, and the handshake must
    // surface that as JoinRejected rather than a spurious Ok.
    let result = create_chat_agent(
        store,
        &ws_url,
        "@no-such-channel-xyz",
        "@hark-test-reject",
        vec!["cite".to_owned()],
        identity,
    )
    .await;

    match result {
        Err(ChatError::JoinRejected(slug)) => {
            eprintln!("hub rejected as expected: {slug}");
            assert_eq!(slug, "no-such-channel");
        }
        Err(other) => panic!("expected JoinRejected, got {other:?}"),
        Ok(_) => panic!("entering a non-existent channel must not succeed"),
    }
}
