//! Live interop test for the cbcl-chat transport (IMPL-003 §6).
//!
//! Proves the hard part: a hark agent's **canonical-encoded, Ed25519-signed**
//! `hello` is accepted by a *real* running cbcl-chat hub — i.e. hark's
//! `ed25519-dalek` signature over canonical CBCL bytes interoperates with the
//! hub's libsodium `verify-sender` (SPEC-001 CON-006). On acceptance the hub
//! replies with a `roomcfg`/`presence` frame; a signature failure would be
//! `bad-signature`.
//!
//! Ignored by default — it needs a hub at ws://localhost:8080/chat/v1
//! (`cd ../cbcl-chat && make shell`). Run with:
//!   cargo test --test chat_live -- --ignored --nocapture

use std::sync::Arc;
use std::time::Duration;

use hark::chat::create_chat_agent;
use hark::daemon::{AgentStore, AgentStoreConfig};
use hark::identity::ChatIdentity;
use url::Url;

#[tokio::test]
#[ignore = "requires a running cbcl-chat hub on ws://localhost:8080/chat/v1"]
async fn signed_hello_is_accepted_by_live_hub() {
    let store = AgentStore::new(AgentStoreConfig {
        agent_id_prefix: "hark-chat-test".to_owned(),
        max_messages_per_handle: 64,
        max_bytes_per_handle: 65_536,
    });
    let identity = Arc::new(ChatIdentity::from_seed([42u8; 32]));
    let ws_url = Url::parse("ws://localhost:8080/chat/v1").expect("valid url");

    let handle = create_chat_agent(
        store.clone(),
        &ws_url,
        "@general",
        "@hark-test",
        vec!["cite".to_owned()],
        identity,
    )
    .await
    .expect("connect + signed hello to live hub");

    // Collect frames for a short window; the hub sends roomcfg + presence on a
    // successful join. A rejected signature would arrive as an error frame.
    let mut saw_roomcfg_or_presence = false;
    let mut saw_bad_signature = false;
    for _ in 0..5 {
        match store.recv(&handle, Some(Duration::from_millis(800))).await {
            Ok(frame) => {
                eprintln!("hub → agent: {frame}");
                if frame.contains("roomcfg") || frame.contains("presence") {
                    saw_roomcfg_or_presence = true;
                }
                if frame.contains("bad-signature") {
                    saw_bad_signature = true;
                }
            }
            Err(_) => break,
        }
    }

    assert!(!saw_bad_signature, "hub rejected the signature — Ed25519/canonical interop is broken");
    assert!(
        saw_roomcfg_or_presence,
        "expected a roomcfg/presence frame confirming the signed hello was accepted"
    );
}
