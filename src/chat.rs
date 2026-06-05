//! Native cbcl-chat transport (SPEC-003 CON-001, IMPL-003 Phase 1/2).
//!
//! A sibling to [`crate::router`] that connects an agent to cbcl-chat's
//! `/chat/v1` WebSocket as an ordinary signed member: it sends an
//! Ed25519-signed `hello` to join a channel, then bridges the socket to the
//! daemon's inbound queue and outbound send channel, exactly as the router
//! transport does. Outbound frames are signed + length-framed (validated CBCL text)
//! (the cbcl-chat frame format); inbound frames have their payload extracted
//! and enqueued (the hub already verified the signer, so we trust delivered
//! frames, like the browser does).
//!
//! V1 scope: membership + recv/reply. The capability filter (answer only
//! learned dialects) and the claim round + RendezvousHash selection
//! (`crate::selector`) layer on top of this loop (IMPL-003 §3); they are
//! additive and do not change the connect/frame path proven here.

use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::{connect_async, tungstenite::Message as WsMessage};
use url::Url;

use crate::chat_frame::{decode_payload, encode_frame};
use crate::daemon::{AgentHandle, AgentSendChannel, AgentStore};
use crate::identity::ChatIdentity;

pub const CHAT_WS_PATH: &str = "/chat/v1";

#[derive(Debug, thiserror::Error)]
pub enum ChatError {
    #[error("chat connection failed: {0}")]
    ConnectionFailed(String),
    #[error("failed to build hello: {0}")]
    Hello(String),
    #[error("failed to send hello: {0}")]
    HelloSendFailed(String),
    #[error("agent store rejected the connection: {0}")]
    Store(String),
}

/// The exact payload bytes to sign and transmit. We validate that `text`
/// parses as CBCL, then sign and send it **verbatim**: the hub verifies the
/// signature over the bytes as received (SPEC-001 CON-006) and parses them, so
/// the bytes signed MUST equal the bytes sent. We do not pre-canonicalise —
/// the hub accepts any well-formed CBCL and canonicalises server-side. (Note:
/// `cbcl_core::canonical_encode` is a binary *content-addressing* form, not the
/// wire text, so it must not be used here.)
fn payload_bytes(text: &str) -> Result<Vec<u8>, String> {
    cbcl_parser::parse(text).map_err(|error| error.to_string())?;
    Ok(text.as_bytes().to_vec())
}

/// Connect to `/chat/v1`, join `channel` as `agent_handle` with a signed
/// `hello`, and spawn the receive loop. Returns the store handle for the
/// connection (used by `recv`/`reply`).
pub async fn create_chat_agent(
    store: AgentStore,
    ws_url: &Url,
    channel: &str,
    agent_handle: &str,
    dialects: Vec<String>,
    identity: Arc<ChatIdentity>,
) -> Result<AgentHandle, ChatError> {
    AgentStore::validate_advertisement(&dialects)
        .map_err(|error| ChatError::Store(error.to_string()))?;
    let (mut websocket, _response) = connect_async(ws_url.as_str())
        .await
        .map_err(|error| ChatError::ConnectionFailed(error.to_string()))?;

    let hello = format!(
        "(hello {channel} :from {agent_handle} :key \"{}\")",
        identity.public_key_b64()
    );
    let payload = payload_bytes(&hello).map_err(ChatError::Hello)?;
    let frame = encode_frame(&payload, identity.as_ref());
    websocket
        .send(WsMessage::Binary(frame.into()))
        .await
        .map_err(|error| ChatError::HelloSendFailed(error.to_string()))?;

    let handle = AgentHandle::generate();
    let (close_tx, close_rx) = oneshot::channel();
    let (send_tx, send_rx) = mpsc::channel(8);
    store
        .insert_connected_with_router_channels(
            handle.clone(),
            dialects,
            Some(close_tx),
            Some(AgentSendChannel::new(send_tx)),
        )
        .await
        .map_err(|error| ChatError::Store(error.to_string()))?;

    spawn_receive_loop(ReceiveLoopArgs {
        store,
        handle: handle.clone(),
        websocket,
        close_rx,
        send_rx,
        identity,
    });

    Ok(handle)
}

struct ReceiveLoopArgs {
    store: AgentStore,
    handle: AgentHandle,
    websocket: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    close_rx: oneshot::Receiver<()>,
    send_rx: mpsc::Receiver<crate::daemon::OutboundFrame>,
    identity: Arc<ChatIdentity>,
}

fn spawn_receive_loop(args: ReceiveLoopArgs) {
    let ReceiveLoopArgs {
        store,
        handle,
        mut websocket,
        mut close_rx,
        mut send_rx,
        identity,
    } = args;
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut close_rx => {
                    let _ = websocket.close(None).await;
                    break;
                }
                outbound = send_rx.recv() => {
                    let Some(outbound) = outbound else {
                        let _ = store.mark_unhealthy(&handle, "local_send_failed", Some("chat send channel closed".to_owned())).await;
                        break;
                    };
                    // Validate + sign + frame on the way out.
                    let payload = match payload_bytes(&outbound.message) {
                        Ok(payload) => payload,
                        Err(error) => {
                            let _ = outbound.result_tx.send(Err(format!("outbound not valid CBCL: {error}")));
                            continue;
                        }
                    };
                    let frame = encode_frame(&payload, identity.as_ref());
                    match websocket.send(WsMessage::Binary(frame.into())).await {
                        Ok(()) => { let _ = outbound.result_tx.send(Ok(())); }
                        Err(error) => {
                            let detail = sanitize(&error.to_string());
                            let _ = outbound.result_tx.send(Err(detail.clone()));
                            let _ = store.mark_unhealthy(&handle, "local_send_failed", Some(detail)).await;
                            break;
                        }
                    }
                }
                message = websocket.next() => {
                    let payload_text = match message {
                        Some(Ok(WsMessage::Binary(bytes))) => {
                            match decode_payload(&bytes) {
                                Some(payload) => String::from_utf8_lossy(payload).into_owned(),
                                None => continue, // malformed frame: drop, keep the connection
                            }
                        }
                        Some(Ok(WsMessage::Text(text))) => text.to_string(),
                        Some(Ok(WsMessage::Close(frame))) => {
                            let detail = frame.map(|f| format!("code={:?} reason=\"{}\"", f.code, f.reason))
                                .unwrap_or_else(|| "no close frame".to_owned());
                            let _ = store.mark_unhealthy(&handle, "hub_closed", Some(sanitize(&detail))).await;
                            break;
                        }
                        None => {
                            let _ = store.mark_unhealthy(&handle, "hub_closed", Some("hub WebSocket stream ended".to_owned())).await;
                            break;
                        }
                        Some(Ok(_)) => continue,
                        Some(Err(error)) => {
                            let _ = store.mark_unhealthy(&handle, "hub_closed", Some(sanitize(&error.to_string()))).await;
                            break;
                        }
                    };
                    if store.enqueue_inbound(&handle, payload_text).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
}

fn sanitize(text: &str) -> String {
    text.chars().take(512).collect()
}

#[cfg(test)]
mod tests {
    use super::payload_bytes;

    #[test]
    fn payload_bytes_validates_and_passes_through() {
        // Parses and re-encodes; the output is valid canonical CBCL bytes.
        let payload = payload_bytes("(hello @general :from @aria :key \"abc\")")
            .expect("hello should canonicalise");
        assert!(!payload.is_empty());
        // Round-trips back through the parser.
        let text = String::from_utf8(payload).unwrap();
        assert!(cbcl_parser::parse(&text).is_ok());
    }

    #[test]
    fn rejects_non_cbcl() {
        assert!(payload_bytes("not (((valid").is_err());
    }
}
