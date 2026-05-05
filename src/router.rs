use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async,
    tungstenite::{Message, client::IntoClientRequest, http::header::InvalidHeaderValue},
};

use crate::{
    config::ValidatedRouterConfig,
    daemon::{AgentHandle, AgentSendChannel, AgentStore},
};

pub const AGENT_WS_PATH: &str = "/agent/v1";

type RouterWebSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CreatedRouterAgent {
    pub agent_handle: AgentHandle,
    pub router_agent_id: String,
    pub capabilities: Vec<String>,
    pub dialects: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum RouterError {
    #[error("router authentication rejected")]
    AuthRejected,
    #[error("router connection failed: {0}")]
    ConnectionFailed(String),
    #[error("failed to send router hello: {0}")]
    HelloSendFailed(String),
}

pub async fn create_router_agent(
    store: AgentStore,
    router: &ValidatedRouterConfig,
    agent_id_prefix: &str,
    capabilities: Vec<String>,
    dialects: Vec<String>,
) -> Result<CreatedRouterAgent, RouterError> {
    AgentStore::validate_advertisement(&capabilities, &dialects)
        .map_err(|error| RouterError::ConnectionFailed(error.to_string()))?;
    let handle = AgentHandle::generate();
    let router_agent_id = format!("{agent_id_prefix}-{}", handle.as_str());
    let mut websocket = connect(router).await?;
    let hello = build_hello_frame(&router_agent_id, &capabilities, &dialects);
    websocket
        .send(Message::Binary(hello.into_bytes().into()))
        .await
        .map_err(|error| RouterError::HelloSendFailed(error.to_string()))?;

    let (close_tx, close_rx) = oneshot::channel();
    let (send_tx, send_rx) = mpsc::channel(8);
    let snapshot = store
        .insert_connected_with_router_channels(
            handle.clone(),
            capabilities.clone(),
            dialects.clone(),
            Some(close_tx),
            Some(AgentSendChannel::new(send_tx)),
        )
        .await
        .map_err(|error| RouterError::ConnectionFailed(error.to_string()))?;
    spawn_receive_loop(store, handle.clone(), websocket, close_rx, send_rx);

    Ok(CreatedRouterAgent {
        agent_handle: handle,
        router_agent_id: snapshot.router_agent_id,
        capabilities,
        dialects,
    })
}

pub fn build_hello_frame(
    router_agent_id: &str,
    capabilities: &[String],
    dialects: &[String],
) -> String {
    format!(
        "(lang cbcl-router (tell @router \"hello\" :agent-id \"{}\" :capabilities ({}) :dialects ({})))",
        escape_cbcl_string(router_agent_id),
        capabilities
            .iter()
            .map(|capability| format!("\"{}\"", escape_cbcl_string(capability)))
            .collect::<Vec<_>>()
            .join(" "),
        dialects
            .iter()
            .map(|dialect| format!("\"{}\"", escape_cbcl_string(dialect)))
            .collect::<Vec<_>>()
            .join(" ")
    )
}

async fn connect(router: &ValidatedRouterConfig) -> Result<RouterWebSocket, RouterError> {
    let mut request = router
        .ws_url
        .as_str()
        .into_client_request()
        .map_err(|error| RouterError::ConnectionFailed(error.to_string()))?;
    request.headers_mut().insert(
        "authorization",
        format!("Bearer {}", router.auth_token)
            .parse()
            .map_err(|error: InvalidHeaderValue| {
                RouterError::ConnectionFailed(error.to_string())
            })?,
    );

    connect_async(request)
        .await
        .map(|(websocket, _response)| websocket)
        .map_err(map_connect_error)
}

fn spawn_receive_loop(
    store: AgentStore,
    handle: AgentHandle,
    mut websocket: RouterWebSocket,
    mut close_rx: oneshot::Receiver<()>,
    mut send_rx: mpsc::Receiver<crate::daemon::OutboundFrame>,
) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut close_rx => {
                    let _ = websocket.close(None).await;
                    break;
                }
                outbound = send_rx.recv() => {
                    let Some(outbound) = outbound else {
                        let _ = store.mark_unhealthy(&handle, "local_send_failed", Some("router send channel closed".to_owned())).await;
                        break;
                    };
                    match websocket.send(Message::Binary(outbound.message.into_bytes().into())).await {
                        Ok(()) => {
                            let _ = outbound.result_tx.send(Ok(()));
                        }
                        Err(error) => {
                            let detail = sanitize_diagnostic(&error.to_string());
                            let _ = outbound.result_tx.send(Err(detail.clone()));
                            let _ = store.mark_unhealthy(&handle, "local_send_failed", Some(detail)).await;
                            break;
                        }
                    }
                }
                message = websocket.next() => {
                    match message {
                        Some(Ok(Message::Binary(bytes))) => {
                            let text = String::from_utf8_lossy(&bytes).into_owned();
                            if is_router_error_frame(&text) {
                                let _ = store.mark_unhealthy(&handle, "router_error", Some(sanitize_diagnostic(&text))).await;
                                break;
                            }
                            if store.enqueue_inbound(&handle, text).await.is_err() {
                                break;
                            }
                        }
                        Some(Ok(Message::Text(text))) => {
                            let text = text.to_string();
                            if is_router_error_frame(&text) {
                                let _ = store.mark_unhealthy(&handle, "router_error", Some(sanitize_diagnostic(&text))).await;
                                break;
                            }
                            if store.enqueue_inbound(&handle, text).await.is_err() {
                                break;
                            }
                        }
                        Some(Ok(Message::Close(_))) | None => {
                            let _ = store.mark_unhealthy(&handle, "router_closed", None).await;
                            break;
                        }
                        Some(Ok(_)) => {}
                        Some(Err(error)) => {
                            let _ = store.mark_unhealthy(&handle, "router_closed", Some(sanitize_diagnostic(&error.to_string()))).await;
                            break;
                        }
                    }
                }
            }
        }
    });
}

fn map_connect_error(error: tokio_tungstenite::tungstenite::Error) -> RouterError {
    match error {
        tokio_tungstenite::tungstenite::Error::Http(response)
            if matches!(response.status().as_u16(), 401 | 403) =>
        {
            RouterError::AuthRejected
        }
        error => RouterError::ConnectionFailed(error.to_string()),
    }
}

fn is_router_error_frame(text: &str) -> bool {
    text.contains("(error") || text.contains(" error ")
}

fn sanitize_diagnostic(text: &str) -> String {
    text.chars().take(512).collect()
}

fn escape_cbcl_string(value: &str) -> String {
    value
        .chars()
        .flat_map(|character| match character {
            '\\' => "\\\\".chars().collect::<Vec<_>>(),
            '"' => "\\\"".chars().collect::<Vec<_>>(),
            _ => vec![character],
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::build_hello_frame;

    #[test]
    fn builds_hello_frame_preserving_order() {
        let frame = build_hello_frame(
            "local-agent-0123456789ABCDEFGHJKMNPQRS",
            &["code:edit".to_owned(), "code:test".to_owned()],
            &["elf".to_owned(), "cbcl-router".to_owned()],
        );

        assert_eq!(
            frame,
            "(lang cbcl-router (tell @router \"hello\" :agent-id \"local-agent-0123456789ABCDEFGHJKMNPQRS\" :capabilities (\"code:edit\" \"code:test\") :dialects (\"elf\" \"cbcl-router\")))"
        );
    }

    #[test]
    fn escapes_hello_strings() {
        let frame = build_hello_frame("agent\"id", &["code\\edit".to_owned()], &[]);

        assert!(frame.contains("\"agent\\\"id\""));
        assert!(frame.contains("\"code\\\\edit\""));
    }
}
