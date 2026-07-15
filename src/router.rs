use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Duration, Instant, MissedTickBehavior};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async, tungstenite::Message as WsMessage,
};

use crate::{
    cbcl_validation::{InboundClass, classify_inbound},
    config::ValidatedRouterConfig,
    daemon::{AgentHandle, AgentSendChannel, AgentStore},
    dialect_cache::DialectCache,
    identity::ChatIdentity,
    signed_transport::{SignedConn, build_router_hello, parse_conn_bootstrap},
};
use cbcl_core::{
    canonical::canonical_encode,
    message::{CorePerformative, Message, Performative},
    sexpr::SExpr,
    store::{ContentHash, ThreadId},
};
use cbcl_parser::{PipelineContext, PipelineResult, run_pipeline_full};
use sha2::{Digest, Sha256};

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
    /// The WebSocket upgrade was refused with HTTP 401/403 — e.g. a proxy in
    /// front of `/agent/v1`. The hub itself has no connection auth (identity is
    /// per-frame Ed25519), so this never originates from the hub.
    #[error("router WebSocket upgrade refused (HTTP 401/403)")]
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
    identity: Arc<ChatIdentity>,
) -> Result<CreatedRouterAgent, RouterError> {
    AgentStore::validate_advertisement(&dialects)
        .map_err(|error| RouterError::ConnectionFailed(error.to_string()))?;
    let handle = AgentHandle::generate();
    let router_agent_id = format!("{agent_id_prefix}-{}", handle.as_str());
    let mut websocket = connect(router).await?;

    // SPEC-012 signed-member connect: the hub issues a conn-nonce bootstrap as
    // its first frame; capture it into a per-connection signer, then send a
    // per-frame-signed hello advertising our Ed25519 key. Identity is the key —
    // there is no bearer token.
    let mut conn = recv_bootstrap(&mut websocket).await?;
    let hello = build_router_hello(&router_agent_id, &identity.public_key_b64(), &dialects);
    let hello_frame = conn.sign_router_frame(&*identity, hello.as_bytes());
    websocket
        .send(WsMessage::Binary(hello_frame.into()))
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
            None, // router derives its wire id from the local handle
            None, // the router transport has no channel
        )
        .await
        .map_err(|error| RouterError::ConnectionFailed(error.to_string()))?;
    // SPEC-009 dialect cache. One per agent — installations made by this
    // session don't leak across sessions, and the cache dies with the
    // WebSocket process when the user disconnects. R5 Phase B moved
    // ownership onto the per-agent `AgentEntry` so both this receive
    // loop AND the outbound send handler in `local_api.rs` can share
    // the same cache.
    let dialect_cache = store
        .dialect_cache_handle(&handle)
        .await
        .map_err(|error| RouterError::ConnectionFailed(error.to_string()))?;
    spawn_receive_loop(ReceiveLoopArgs {
        store,
        handle: handle.clone(),
        websocket,
        close_rx,
        send_rx,
        dialect_cache,
        router_agent_id: snapshot.router_agent_id.clone(),
        initial_dialects: dialects.clone(),
        conn,
        identity,
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

/// Connect to the router's `/agent/v1` WebSocket. SPEC-012 REQ-009: NO bearer /
/// challenge-response connection auth — identity is established per-frame by
/// Ed25519 signature (see the signed hello below). TLS (wss) secures the channel.
async fn connect(router: &ValidatedRouterConfig) -> Result<RouterWebSocket, RouterError> {
    connect_async(router.ws_url.as_str())
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
    /// Per-connection signer (conn_nonce + hub_id + seq) for every outbound frame.
    conn: SignedConn,
    /// The agent's Ed25519 identity key.
    identity: Arc<ChatIdentity>,
}

/// How long to wait for the hub's conn-nonce bootstrap before giving up — a hub
/// that accepts the upgrade then stalls must not hang `create_router_agent`.
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(10);

/// Receive + parse the hub's conn-nonce bootstrap (its first frame), yielding a
/// `SignedConn` primed with the connection's `conn_nonce` + `hub_id`.
async fn recv_bootstrap(ws: &mut RouterWebSocket) -> Result<SignedConn, RouterError> {
    let msg = match tokio::time::timeout(BOOTSTRAP_TIMEOUT, ws.next()).await {
        Err(_) => {
            return Err(RouterError::ConnectionFailed(
                "timed out waiting for the conn-nonce bootstrap".into(),
            ));
        }
        Ok(None) => {
            return Err(RouterError::ConnectionFailed(
                "closed before conn-nonce bootstrap".into(),
            ));
        }
        Ok(Some(Err(error))) => return Err(RouterError::ConnectionFailed(error.to_string())),
        Ok(Some(Ok(msg))) => msg,
    };
    let text = match msg {
        WsMessage::Binary(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        WsMessage::Text(text) => text.to_string(),
        other => {
            return Err(RouterError::ConnectionFailed(format!(
                "unexpected first frame (expected conn-nonce bootstrap): {other:?}"
            )));
        }
    };
    let boot = parse_conn_bootstrap(&text).ok_or_else(|| {
        RouterError::ConnectionFailed(format!(
            "first frame was not a conn-nonce bootstrap: {text}"
        ))
    })?;
    Ok(SignedConn::from_bootstrap(&boot))
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
        mut conn,
        identity,
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
                    let hb = conn.sign_router_frame(&*identity, HEARTBEAT_FRAME.as_bytes());
                    if let Err(error) = websocket.send(WsMessage::Binary(hb.into())).await {
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
                    let frame = conn.sign_router_frame(&*identity, outbound.message.as_bytes());
                    match websocket.send(WsMessage::Binary(frame.into())).await {
                        Ok(()) => {
                            let _ = outbound.result_tx.send(Ok(()));
                        }
                        Err(error) => {
                            let detail = sanitize_diagnostic(&error.to_string());
                            // The router transport carries no MLS encryption, so a
                            // send failure here is always a dead socket — fatal.
                            let _ = outbound.result_tx.send(Err(crate::daemon::OutboundReject::fatal(detail.clone())));
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
                                let hello = build_router_hello(
                                    &router_agent_id,
                                    &identity.public_key_b64(),
                                    &advertised,
                                );
                                let hello_frame = conn.sign_router_frame(&*identity, hello.as_bytes());
                                if let Err(error) = websocket
                                    .send(WsMessage::Binary(hello_frame.into()))
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
    // Cache install runs on every DialectPush regardless of routing —
    // teach-back responses to a `query (speak? X)` install identically to
    // subscriber pushes, so the daemon-local cache is kept consistent
    // whichever path produced the frame. Re-install is idempotent under
    // content addressing.
    let mut installed: Option<String> = None;
    let delivery = match &class {
        InboundClass::DialectPush {
            name, define_form, ..
        } => match dialect_cache.try_install(name, define_form) {
            Ok(digest) => {
                tracing::info!(
                    target = "hark::dialect_cache",
                    name = %name,
                    digest = %digest,
                    "installed pushed dialect"
                );
                installed = Some(name.clone());
                Some(crate::daemon::MetaReplyDelivery::PushInstalled {
                    name: name.clone(),
                    define_form: define_form.clone(),
                    digest,
                    frame: text.clone(),
                })
            }
            Err(error) => {
                tracing::warn!(
                    target = "hark::dialect_cache",
                    name = %name,
                    error = %error,
                    "pushed dialect failed R1–R5; not cached"
                );
                Some(crate::daemon::MetaReplyDelivery::PushInstallFailed {
                    name: name.clone(),
                    reason: error.to_string(),
                    frame: text.clone(),
                })
            }
        },
        InboundClass::MetaReply => Some(crate::daemon::MetaReplyDelivery::Reply(text.clone())),
        _ => None,
    };
    // Meta-reply correlation: only consume frames whose shape matches the
    // pending caller's expectation. An unrelated dialect push arriving while
    // `publish`/`list`/`query` is in flight falls through to the inbound
    // queue so it can't be misrouted as the awaited reply.
    let (text, fell_through_meta) = if let Some(delivery) = delivery {
        match store.try_route_meta_reply(handle, delivery).await {
            None => {
                if let Some(name) = installed {
                    return InboundOutcome::Installed(name);
                }
                return InboundOutcome::Continue;
            }
            Some(text) => (text, true),
        }
    } else {
        (text, false)
    };

    // R5 Phase C: runtime shape + causal verification on inbound ordinary
    // frames (REQ-231). Meta pushes / meta-replies that fell through from
    // the meta-reply correlator skip this gate — pushes were already
    // R1–R5-checked in `dialect_cache.try_install`, and a stray reply has
    // no expanded payload to shape-check. Only frames that classify as
    // Ordinary carry an applicative simple message whose registry-resident
    // shape/causal protocol we need to enforce here.
    if matches!(class, InboundClass::Ordinary) && !fell_through_meta {
        match verify_inbound_against_registry(store, handle, dialect_cache, &text).await {
            InboundVerification::Accept(append) => {
                if let Some(boxed) = append {
                    let (hash, thread, message) = *boxed;
                    if let Err(error) = store.append_message(handle, hash, thread, message).await {
                        // Unknown-handle path: agent went away mid-frame.
                        // Treat as fatal for the receive loop.
                        tracing::warn!(
                            target: "hark::r5",
                            error = %error,
                            "failed to append inbound message to causal store"
                        );
                        return InboundOutcome::Exit;
                    }
                }
            }
            InboundVerification::Drop => {
                // Violation already logged at warn level; do not enqueue.
                return InboundOutcome::Continue;
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

/// Outcome of running the full R5 pipeline against an inbound ordinary
/// frame. `Accept` carries an optional triple to append to the agent's
/// causal store (REQ-310 dedup is handled by the store itself); `Drop`
/// means the frame violated shape or causal protocol and MUST NOT reach
/// the recv queue. The triple is boxed to keep the enum's discriminant
/// cheap — `Message` is ~232 bytes and `Drop` is the common steady-state
/// for violating frames.
enum InboundVerification {
    Accept(Option<Box<(ContentHash, ThreadId, Message)>>),
    Drop,
}

/// Run `run_pipeline_full` for one inbound `(lang ...)` / bare-message
/// frame against the agent's registry snapshot + per-handle causal store.
///
/// On `Success`, computes the canonical content hash so the caller can
/// append the message into the store before delivering — this is what
/// makes subsequent inbound frames in the same thread see this message
/// as a valid `:caused-by` predecessor.
///
/// On `ValidationError::ShapeViolation` / `CausalViolation` or `Pending`,
/// emits a structured `tracing::warn` and returns `Drop`. Other pipeline
/// failures (`ParseError`, malformed messages, R1–R4 meta-envelope
/// validation, unknown-dialect eval errors, and `Buffered` under a
/// non-Reject policy) fall through to the existing enqueue path: Phase
/// C's contract is shape + causal enforcement only; dropping on
/// unknown-dialect would break agents that advertise a dialect name
/// before the matching `(define ...)` push has arrived.
async fn verify_inbound_against_registry(
    store: &AgentStore,
    handle: &AgentHandle,
    dialect_cache: &DialectCache,
    text: &str,
) -> InboundVerification {
    let registry = dialect_cache.registry_snapshot();
    let store_arc = match store.store_handle(handle).await {
        Ok(arc) => arc,
        Err(error) => {
            tracing::warn!(
                target: "hark::r5",
                error = %error,
                "failed to acquire causal store for inbound verification"
            );
            return InboundVerification::Drop;
        }
    };

    let result = {
        let guard = store_arc.lock().await;
        let ctx = PipelineContext::new(&registry, &*guard);
        run_pipeline_full(text, &ctx)
    };

    match result {
        PipelineResult::Success(message) => {
            let append = build_store_entry(&message).map(Box::new);
            InboundVerification::Accept(append)
        }
        PipelineResult::ValidationError(ref error)
            if matches!(
                error,
                cbcl_parser::ValidationError::ShapeViolation { .. }
                    | cbcl_parser::ValidationError::CausalViolation { .. }
            ) =>
        {
            let (performative, thread, blame) = describe_violation(error);
            tracing::warn!(
                target: "hark::r5",
                performative = ?performative,
                thread = ?thread,
                blame = %blame,
                "inbound r5 violation, dropping"
            );
            InboundVerification::Drop
        }
        PipelineResult::Pending { reason, message } => {
            let thread = message.thread().map(String::from);
            let performative = message.performative().map(|p| p.name().to_owned());
            tracing::warn!(
                target: "hark::r5",
                performative = ?performative,
                thread = ?thread,
                reason = ?reason,
                "inbound r5 pending (unknown causal predecessor), dropping"
            );
            InboundVerification::Drop
        }
        // Everything else — `ParseError`, malformed message, R1–R4 meta
        // envelope errors, eval errors like `UnknownDialect`, and
        // `Buffered` under a non-Reject policy — passes through. The
        // existing enqueue path remains the system of record for those
        // frames.
        PipelineResult::ValidationError(_)
        | PipelineResult::ParseError(_)
        | PipelineResult::Buffered { .. } => InboundVerification::Accept(None),
    }
}

/// Build the `(hash, thread, message)` triple for the per-handle causal
/// store. Only `Simple` messages reach here (via `innermost_simple` —
/// `Dialect` and `Wrapped` defer to their inner). Meta messages are not
/// expected on the Ordinary path; returning `None` for them is a safe
/// no-op (the frame still enqueues; the store just doesn't grow).
fn build_store_entry(message: &Message) -> Option<(ContentHash, ThreadId, Message)> {
    let simple = message.innermost_simple()?;
    let Message::Simple { thread, .. } = simple else {
        return None;
    };
    let thread_id = ThreadId(thread.clone().unwrap_or_else(|| String::from("default")));
    let sexpr: SExpr = simple.into();
    let bytes = canonical_encode(&sexpr);
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let digest = format!("sha256:{:x}", hasher.finalize());
    Some((ContentHash(digest), thread_id, simple.clone()))
}

/// Extract performative / thread / blame s-expr from a pipeline
/// `ValidationError` for the `hark::r5` warn-log. Shape and causal
/// variants carry a structured `ViolationError`; the rest fall back to
/// the `Display` impl.
fn describe_violation(
    error: &cbcl_parser::ValidationError,
) -> (Option<String>, Option<String>, String) {
    use cbcl_parser::ValidationError;
    match error {
        ValidationError::ShapeViolation { blame, .. }
        | ValidationError::CausalViolation { blame, .. } => {
            let performative = blame.performative.clone();
            let thread = blame.thread_id.clone();
            (performative, thread, blame.to_string())
        }
        other => (None, None, other.to_string()),
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

    // R5 Phase C: end-to-end check that `process_inbound` enforces shape
    // contracts. With a dialect installed whose `(shape greet …)` requires
    // `:target` on the expanded form, an inbound `(lang greet-d (greet
    // :name "alice" :thread "rcp-1"))` (missing `:target`) MUST be dropped
    // before reaching the recv queue.
    #[tokio::test]
    async fn process_inbound_drops_ordinary_frame_failing_shape_check() {
        use crate::daemon::{AgentHandle, AgentStore, AgentStoreConfig};
        use tokio::time::{Duration, timeout};

        let store = AgentStore::new(AgentStoreConfig {
            agent_id_prefix: "local-agent".to_owned(),
            max_messages_per_handle: 16,
            max_bytes_per_handle: 4096,
        });
        let handle =
            AgentHandle::new("0123456789ABCDEFGHJKMNPQRS").expect("handle should be valid");
        store
            .insert_connected(handle.clone(), vec!["greet-d".to_owned()])
            .await
            .expect("agent insert should succeed");

        // Install a dialect whose shape on `greet` requires `:target`.
        // The performative expands to `(greet-action …)`; the shape is
        // attached to the `greet` performative name so the pipeline
        // applies it after expansion (REQ-223, REQ-231 step 6b).
        let cache = store
            .dialect_cache_handle(&handle)
            .await
            .expect("cache handle should resolve");
        let define = "(define greet-d (cbcl) @author \
            (extend greet (name) (effect greet-action)) \
            (shape greet (require :target string)))";
        cache
            .try_install("greet-d", define)
            .expect("R5-clean fixture must install");

        // Missing :target — must fail the shape and be dropped.
        let frame = r#"(lang greet-d (greet :name "alice" :thread "rcp-1"))"#;
        let outcome = super::process_inbound(&store, &handle, &cache, frame.to_owned()).await;
        assert!(matches!(outcome, super::InboundOutcome::Continue));

        // A short-timeout recv must time out — nothing should have been
        // enqueued by `process_inbound`.
        let recv = timeout(
            Duration::from_millis(50),
            store.recv(&handle, Some(Duration::from_millis(10))),
        )
        .await
        .expect("outer timeout must not fire before inner");
        assert!(
            matches!(recv, Err(crate::daemon::AgentError::RecvTimeout)),
            "expected RecvTimeout, got {recv:?}"
        );
    }
}
