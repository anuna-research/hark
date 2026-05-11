use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Duration, Instant, MissedTickBehavior};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async,
    tungstenite::{
        Message as WsMessage, client::IntoClientRequest, http::header::InvalidHeaderValue,
    },
};

use crate::{
    cbcl_validation::{InboundClass, classify_inbound},
    config::ValidatedRouterConfig,
    daemon::{AgentHandle, AgentSendChannel, AgentStore},
    dialect_cache::DialectCache,
};
use cbcl_core::message::{CorePerformative, Message, Performative};

pub const AGENT_WS_PATH: &str = "/agent/v1";
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const HEARTBEAT_FRAME: &str = r#"(lang cbcl-router (tell @router "heartbeat"))"#;

type RouterWebSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CreatedRouterAgent {
    pub agent_handle: AgentHandle,
    pub router_agent_id: String,
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
    dialects: Vec<String>,
) -> Result<CreatedRouterAgent, RouterError> {
    AgentStore::validate_advertisement(&dialects)
        .map_err(|error| RouterError::ConnectionFailed(error.to_string()))?;
    let handle = AgentHandle::generate();
    let router_agent_id = format!("{agent_id_prefix}-{}", handle.as_str());
    let mut websocket = connect(router).await?;
    let hello = build_hello_frame(&router_agent_id, &dialects);
    websocket
        .send(WsMessage::Binary(hello.into_bytes().into()))
        .await
        .map_err(|error| RouterError::HelloSendFailed(error.to_string()))?;

    let (close_tx, close_rx) = oneshot::channel();
    let (send_tx, send_rx) = mpsc::channel(8);
    let snapshot = store
        .insert_connected_with_router_channels(
            handle.clone(),
            dialects.clone(),
            Some(close_tx),
            Some(AgentSendChannel::new(send_tx)),
        )
        .await
        .map_err(|error| RouterError::ConnectionFailed(error.to_string()))?;
    // SPEC-009 dialect cache. One per agent — installations made by this
    // session don't leak across sessions, and the cache dies with the
    // WebSocket process when the user disconnects.
    let dialect_cache = DialectCache::new();
    spawn_receive_loop(ReceiveLoopArgs {
        store,
        handle: handle.clone(),
        websocket,
        close_rx,
        send_rx,
        dialect_cache,
        router_agent_id: snapshot.router_agent_id.clone(),
        initial_dialects: dialects.clone(),
    });

    Ok(CreatedRouterAgent {
        agent_handle: handle,
        router_agent_id: snapshot.router_agent_id,
        dialects,
    })
}

/// `(lang cbcl-router (tell @router "hello" :agent-id "..." :dialects (...)))`.
///
/// SPEC-009 collapses capability ≡ dialect; the router routes by dialect
/// identity and silently ignores `:capabilities`. We drop the field from the
/// wire payload here.
pub fn build_hello_frame(router_agent_id: &str, dialects: &[String]) -> String {
    format!(
        "(lang cbcl-router (tell @router \"hello\" :agent-id \"{}\" :dialects ({})))",
        escape_cbcl_string(router_agent_id),
        dialects
            .iter()
            .map(|dialect| format!("\"{}\"", escape_cbcl_string(dialect)))
            .collect::<Vec<_>>()
            .join(" ")
    )
}

// ---------------------------------------------------------------------------
// SPEC-009 meta-message frame builders.
//
// These produce CBCL bytes for the three meta verbs the router handles. They
// are intentionally simple string builders: the bodies fed to teach are
// expected to be already-canonical CBCL define forms (validated upstream by
// cbcl_parser::run_pipeline before being handed here), so we just emit them
// verbatim inside the (meta (teach @router ...)) envelope.
// ---------------------------------------------------------------------------

/// `(meta (teach @router <define-form>))` — publish a dialect to the router.
/// `define_form` is the raw `(define <name> ...)` CBCL bytes; the caller is
/// responsible for having parsed/validated it. The router stores the inner
/// define content-addressed (SHA-256 of canonical bytes) and broadcasts to
/// subscribers whose pattern matches the dialect name.
pub fn build_meta_teach_frame(define_form: &str) -> String {
    format!("(meta (teach @router {define_form}))")
}

/// `(meta (query (speak? <name>)))` — ask the router whether it has a dialect
/// by that name. The router replies in-band with
/// `(meta (teach @<asker> (define <name> ...)))` if it does, or an error
/// reply otherwise. Names are CBCL symbols, not strings, per the meta
/// grammar in cbcl-rs.
pub fn build_meta_query_frame(name: &str) -> String {
    format!("(meta (query (speak? {name})))")
}

/// `(meta (subscribe (speak? <pattern>)))` — subscribe to push announcements
/// for any dialect whose name matches `pattern`. Pattern grammar (slice 2):
/// exact name, `<prefix>*`, or `*` for all. The router pins the subscription
/// to the WebSocket pid; on disconnect the subscription is auto-evicted.
pub fn build_meta_subscribe_frame(pattern: &str) -> String {
    format!("(meta (subscribe (speak? {pattern})))")
}

/// `(meta (unsubscribe))` — drop the agent's subscription without closing
/// the WebSocket. Pattern-less: the router keys subscriptions by the
/// agent's connected pid and stores at most one entry per agent.
pub fn build_meta_unsubscribe_frame() -> String {
    "(meta (unsubscribe))".to_owned()
}

/// `(meta (query (list)))` — enumerate every dialect the router knows. The
/// router replies with `(reply @<asker> "ok" :thread "..." :names "a b c")`,
/// space-separated. Slice-3 router protocol addition.
pub fn build_meta_query_list_frame() -> String {
    "(meta (query (list)))".to_owned()
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

struct ReceiveLoopArgs {
    store: AgentStore,
    handle: AgentHandle,
    websocket: RouterWebSocket,
    close_rx: oneshot::Receiver<()>,
    send_rx: mpsc::Receiver<crate::daemon::OutboundFrame>,
    dialect_cache: DialectCache,
    router_agent_id: String,
    initial_dialects: Vec<String>,
}

fn spawn_receive_loop(args: ReceiveLoopArgs) {
    let ReceiveLoopArgs {
        store,
        handle,
        mut websocket,
        mut close_rx,
        mut send_rx,
        dialect_cache,
        router_agent_id,
        initial_dialects,
    } = args;
    tokio::spawn(async move {
        // Tracks dialects currently advertised by THIS session. Mutated on
        // successful push install so we can emit a fresh hello — the
        // router treats same-pid re-hello as an update (counters and
        // monitors preserved per SPEC-009).
        let mut advertised: Vec<String> = initial_dialects;
        let mut heartbeat =
            tokio::time::interval_at(Instant::now() + HEARTBEAT_INTERVAL, HEARTBEAT_INTERVAL);
        heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = &mut close_rx => {
                    let _ = websocket.close(None).await;
                    break;
                }
                _ = heartbeat.tick() => {
                    if let Err(error) = websocket.send(WsMessage::Binary(HEARTBEAT_FRAME.as_bytes().to_vec().into())).await {
                        let detail = sanitize_diagnostic(&format!("heartbeat send failed: {error}"));
                        let _ = store.mark_unhealthy(&handle, "local_send_failed", Some(detail)).await;
                        break;
                    }
                }
                outbound = send_rx.recv() => {
                    let Some(outbound) = outbound else {
                        let _ = store.mark_unhealthy(&handle, "local_send_failed", Some("router send channel closed".to_owned())).await;
                        break;
                    };
                    match websocket.send(WsMessage::Binary(outbound.message.into_bytes().into())).await {
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
                    let text = match message {
                        Some(Ok(WsMessage::Binary(bytes))) => {
                            String::from_utf8_lossy(&bytes).into_owned()
                        }
                        Some(Ok(WsMessage::Text(text))) => text.to_string(),
                        Some(Ok(WsMessage::Close(close_frame))) => {
                            let detail = close_frame_detail(close_frame);
                            let _ = store.mark_unhealthy(&handle, "router_closed", Some(detail)).await;
                            break;
                        }
                        None => {
                            let _ = store.mark_unhealthy(&handle, "router_closed", Some("router WebSocket stream ended".to_owned())).await;
                            break;
                        }
                        Some(Ok(_)) => continue,
                        Some(Err(error)) => {
                            let _ = store.mark_unhealthy(&handle, "router_closed", Some(sanitize_diagnostic(&error.to_string()))).await;
                            break;
                        }
                    };
                    match process_inbound(&store, &handle, &dialect_cache, text).await {
                        InboundOutcome::Exit => break,
                        InboundOutcome::Continue => {}
                        InboundOutcome::Installed(name) => {
                            if !advertised.contains(&name) {
                                advertised.push(name.clone());
                                let hello = build_hello_frame(&router_agent_id, &advertised);
                                if let Err(error) = websocket
                                    .send(WsMessage::Binary(hello.into_bytes().into()))
                                    .await
                                {
                                    let detail = sanitize_diagnostic(&format!(
                                        "auto re-hello after installing dialect {name} failed: {error}"
                                    ));
                                    let _ = store
                                        .mark_unhealthy(&handle, "local_send_failed", Some(detail))
                                        .await;
                                    break;
                                }
                                tracing::info!(
                                    target = "hark::router",
                                    dialect = %name,
                                    "auto re-hello with new dialect"
                                );
                            }
                        }
                    }
                }
            }
        }
    });
}

/// Outcome of processing one inbound frame. Drives the receive loop's
/// auto-rehello logic — `Installed(name)` is the signal to emit a fresh
/// hello carrying the updated dialect set.
enum InboundOutcome {
    Continue,
    Exit,
    Installed(String),
}

/// Process one inbound text/binary frame from the router.
///
/// Order of checks:
///   1. Router-emitted `error` frame → mark unhealthy and `Exit`.
///   2. Classify via [`classify_inbound`]. A `DialectPush` is the SPEC-009
///      subscription fan-out; install into the cache (R1–R5-checked via
///      cbcl-rs's pipeline). On success returns `Installed(name)` so the
///      caller can auto re-hello with the new dialect added. On failure
///      log + continue (push still forwarded so the user can investigate).
///   3. Everything else (replies, dispatched asks, progress) → forward as
///      `Continue`.
async fn process_inbound(
    store: &AgentStore,
    handle: &AgentHandle,
    dialect_cache: &DialectCache,
    text: String,
) -> InboundOutcome {
    if is_router_error_frame(&text) {
        let _ = store
            .mark_unhealthy(handle, "router_error", Some(sanitize_diagnostic(&text)))
            .await;
        return InboundOutcome::Exit;
    }
    let class = classify_inbound(&text);
    // Meta-reply correlation: if a `send_meta_and_await` call is in flight
    // for this agent, route the next reply / teach-back to it instead of
    // forwarding to the recv queue. Falls through when nobody is waiting.
    let text = if matches!(class, InboundClass::DialectPush { .. } | InboundClass::MetaReply) {
        match store.try_route_meta_reply(handle, text).await {
            None => return InboundOutcome::Continue,
            Some(text) => text,
        }
    } else {
        text
    };
    let mut installed: Option<String> = None;
    if let InboundClass::DialectPush {
        name, define_form, ..
    } = &class
    {
        match dialect_cache.try_install(name, define_form) {
            Ok(digest) => {
                tracing::info!(
                    target = "hark::dialect_cache",
                    name = %name,
                    digest = %digest,
                    "installed pushed dialect"
                );
                installed = Some(name.clone());
            }
            Err(error) => {
                tracing::warn!(
                    target = "hark::dialect_cache",
                    name = %name,
                    error = %error,
                    "pushed dialect failed R1–R5; not cached"
                );
            }
        }
    }
    if store.enqueue_inbound(handle, text).await.is_err() {
        return InboundOutcome::Exit;
    }
    match installed {
        Some(name) => InboundOutcome::Installed(name),
        None => InboundOutcome::Continue,
    }
}

fn close_frame_detail(
    close_frame: Option<tokio_tungstenite::tungstenite::protocol::CloseFrame>,
) -> String {
    match close_frame {
        Some(frame) => sanitize_diagnostic(&format!(
            "router WebSocket closed: code={:?} reason=\"{}\"",
            frame.code, frame.reason
        )),
        None => "router WebSocket closed without close frame".to_owned(),
    }
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
    let Ok(sexpr) = cbcl_parser::parse(text) else {
        return false;
    };
    let Ok(message) = cbcl_parser::parse_message(&sexpr) else {
        return false;
    };
    matches!(
        message.innermost_simple(),
        Some(Message::Simple {
            performative: Performative::Core(CorePerformative::Error),
            ..
        })
    )
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
    use super::{
        build_hello_frame, build_meta_query_frame, build_meta_query_list_frame,
        build_meta_subscribe_frame, build_meta_teach_frame, build_meta_unsubscribe_frame,
        is_router_error_frame,
    };

    #[test]
    fn builds_hello_frame_preserving_order() {
        let frame = build_hello_frame(
            "local-agent-0123456789ABCDEFGHJKMNPQRS",
            &["elf".to_owned(), "cbcl-router".to_owned()],
        );

        assert_eq!(
            frame,
            "(lang cbcl-router (tell @router \"hello\" :agent-id \"local-agent-0123456789ABCDEFGHJKMNPQRS\" :dialects (\"elf\" \"cbcl-router\")))"
        );
    }

    #[test]
    fn hello_frame_omits_capabilities() {
        // SPEC-009: capability ≡ dialect; the router no longer routes on
        // :capabilities so we drop the field from the wire payload.
        let frame = build_hello_frame("agent-1", &["d".to_owned()]);
        assert!(!frame.contains("capabilities"));
    }

    #[test]
    fn escapes_hello_strings() {
        let frame = build_hello_frame("agent\"id", &["code\\edit".to_owned()]);

        assert!(frame.contains("\"agent\\\"id\""));
        assert!(frame.contains("\"code\\\\edit\""));
    }

    #[test]
    fn detects_bare_and_wrapped_router_error_frames() {
        assert!(is_router_error_frame(r#"(error "bad hello")"#));
        assert!(is_router_error_frame(
            r#"(lang cbcl-router (error @router "bad hello"))"#
        ));
    }

    #[test]
    fn does_not_treat_error_text_as_router_error_frame() {
        assert!(!is_router_error_frame(
            r#"(lang elf (ask @router "contains (error text" :thread "rcp-1"))"#
        ));
        assert!(!is_router_error_frame("not cbcl (error"));
    }

    #[test]
    fn meta_teach_frame_wraps_define_for_router() {
        let frame = build_meta_teach_frame("(define arena-v1 (cbcl) @author)");
        assert_eq!(
            frame,
            "(meta (teach @router (define arena-v1 (cbcl) @author)))"
        );
    }

    #[test]
    fn meta_query_frame_uses_speak_predicate() {
        let frame = build_meta_query_frame("arena-v1");
        assert_eq!(frame, "(meta (query (speak? arena-v1)))");
    }

    #[test]
    fn meta_subscribe_frame_uses_speak_predicate() {
        let exact = build_meta_subscribe_frame("arena-v1");
        let prefix = build_meta_subscribe_frame("arena-*");
        let wildcard = build_meta_subscribe_frame("*");
        assert_eq!(exact, "(meta (subscribe (speak? arena-v1)))");
        assert_eq!(prefix, "(meta (subscribe (speak? arena-*)))");
        assert_eq!(wildcard, "(meta (subscribe (speak? *)))");
    }

    #[test]
    fn meta_unsubscribe_frame_has_no_parameters() {
        assert_eq!(build_meta_unsubscribe_frame(), "(meta (unsubscribe))");
    }

    #[test]
    fn meta_query_list_frame_has_no_parameters() {
        assert_eq!(build_meta_query_list_frame(), "(meta (query (list)))");
    }
}
