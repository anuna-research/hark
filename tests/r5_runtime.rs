//! Integration tests for R5 runtime behavioural contracts.
//!
//! Drives the full daemon path (HTTP send + WebSocket inbound) against a
//! controllable mock router so that shape (REQ-220) and causal (REQ-200)
//! verification on outbound (`local_api::send`) and inbound
//! (`router::process_inbound`) are exercised end-to-end.
//!
//! These complement the unit-level coverage in `cbcl_validation.rs` and
//! `router.rs` by asserting the HTTP error codes, queue state, and
//! per-handle causal store stay consistent.

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use cbcl_core::{
    canonical::canonical_encode, message::Message, sexpr::SExpr, store::ContentHash,
};
use cbcl_parser::{parse, parse_message};
use futures_util::{SinkExt, StreamExt};
use hark::{
    config::AppConfig,
    constants::LOCAL_API_VERSION,
    daemon::{AgentHandle, AgentStore, AgentStoreConfig, DiscoveryRecord},
    local_api::{CreateAgentResponse, ErrorResponse, serve_local_api_with_agents},
};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tokio::{
    net::TcpListener,
    sync::oneshot,
    task::JoinHandle,
    time::{Duration, timeout},
};
use tokio_tungstenite::{accept_async, tungstenite::Message as WsMessage};

// ---------------------------------------------------------------------------
// Fixture: a tiny R1–R5-clean dialect with both shape and causal protocol.
//
// `greet` performative requires `:target string`.
// Protocol: begin → (any greet reply). Both edges allow `:caused-by "begin"`.
// `reply` is referenced via the `cbcl` ancestor so the protocol step resolves
// without needing to redefine a core performative (R3).
// ---------------------------------------------------------------------------
const FIXTURE_NAME: &str = "greet-d";
const FIXTURE_DEFINE: &str = "(define greet-d (cbcl) @author \
    (extend greet (target) (effect greet-action)) \
    (protocol (then begin (any greet reply))) \
    (shape greet (require :target string)))";

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

#[tokio::test]
async fn outbound_shape_violation_is_rejected_with_422() {
    let harness = Harness::start().await;
    let created = harness.create_agent_with_fixture().await;

    // `:caused-by "begin"` satisfies the protocol predecessor so the pipeline
    // proceeds past the causal check (REQ-231 step 6a) and tries the shape
    // rule (step 6b), which then fires for the missing `:target`.
    let response = harness
        .post_send(
            &created.agent_handle,
            "reply",
            r#"(lang greet-d (greet :thread "t-1" :caused-by "begin"))"#,
        )
        .await
        .expect("send request must complete");

    assert_eq!(response.status(), reqwest::StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(error_code(response).await, "shape_violation");

    // No frame should have reached the router.
    assert!(harness.router.captured_frame().is_none());
    harness.shutdown().await;
}

#[tokio::test]
async fn outbound_causal_violation_is_rejected_with_422() {
    let harness = Harness::start().await;
    let created = harness.create_agent_with_fixture().await;

    let response = harness
        .post_send(
            &created.agent_handle,
            "reply",
            r#"(lang greet-d (greet :target "x" :thread "t-1" :caused-by "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"))"#,
        )
        .await
        .expect("send request must complete");

    assert_eq!(response.status(), reqwest::StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(error_code(response).await, "causal_violation");

    assert!(harness.router.captured_frame().is_none());
    harness.shutdown().await;
}

#[tokio::test]
async fn outbound_r5_error_body_includes_performative_and_thread_blame() {
    // P3: spec advertises that R5 violations surface `performative` and
    // `thread` alongside `code`/`message` in the 422 payload so callers
    // can route the rejection without re-parsing the message body. Pre-fix
    // those fields were discarded by the error mapping arms.
    let harness = Harness::start().await;
    let created = harness.create_agent_with_fixture().await;

    let response = harness
        .post_send(
            &created.agent_handle,
            "reply",
            r#"(lang greet-d (greet :thread "t-blame" :caused-by "begin"))"#,
        )
        .await
        .expect("send request must complete");
    assert_eq!(response.status(), reqwest::StatusCode::UNPROCESSABLE_ENTITY);

    let body = error_body(response).await;
    assert_eq!(body.code, "shape_violation");
    assert_eq!(
        body.performative.as_deref(),
        Some("greet"),
        "shape_violation must surface the offending performative",
    );
    assert_eq!(
        body.thread.as_deref(),
        Some("t-blame"),
        "shape_violation must surface the offending :thread",
    );
    harness.shutdown().await;
}

#[tokio::test]
async fn outbound_happy_path_succeeds_and_appends_to_store() {
    let harness = Harness::start().await;
    let created = harness.create_agent_with_fixture().await;

    // Use `reply` (core, allowed by protocol step `(any greet reply)`) with
    // `:caused-by "begin"` so the protocol predecessor resolves to the
    // BEGIN sentinel rather than requiring a hash in the store.
    let message = r#"(lang greet-d (reply "ok" :thread "t-1" :caused-by "begin"))"#;
    let response = harness
        .post_send(&created.agent_handle, "reply", message)
        .await
        .expect("send request must complete");
    assert!(
        response.status().is_success(),
        "expected success, got {}: {}",
        response.status(),
        response.text().await.unwrap_or_default()
    );

    // The frame must have been forwarded to the router.
    harness.router.wait_for_captured_frame(Duration::from_secs(1)).await;
    assert_eq!(harness.router.captured_frame().as_deref(), Some(message));

    // The validated simple message must now be in the per-handle store.
    let handle =
        AgentHandle::new(created.agent_handle.clone()).expect("returned handle must be valid");
    let expected_hash = canonical_simple_hash(message).expect("hash computation must succeed");
    let stored = harness
        .agents
        .lookup_message(&handle, &expected_hash)
        .await
        .expect("lookup must not error");
    assert!(
        stored.is_some(),
        "outbound message must have been appended to the per-handle store"
    );

    harness.shutdown().await;
}

#[tokio::test]
async fn inbound_shape_violation_is_dropped() {
    let harness = Harness::start().await;
    let created = harness.create_agent_with_fixture().await;
    let handle =
        AgentHandle::new(created.agent_handle.clone()).expect("returned handle must be valid");

    // Push an Ordinary frame from the router. `:caused-by "begin"` clears
    // the causal check so the shape rule on `greet` (missing `:target`)
    // is the violation that drops the frame.
    harness
        .router
        .dispatch(r#"(lang greet-d (greet :thread "t-2" :caused-by "begin"))"#)
        .await;

    // Recv should time out — nothing reached the queue.
    let result = timeout(
        Duration::from_millis(250),
        harness.agents.recv(&handle, Some(Duration::from_millis(150))),
    )
    .await
    .expect("outer timeout must not fire before inner");
    assert!(
        matches!(result, Err(hark::daemon::AgentError::RecvTimeout)),
        "expected RecvTimeout, got {result:?}"
    );

    harness.shutdown().await;
}

#[tokio::test]
async fn inbound_causal_violation_is_dropped() {
    let harness = Harness::start().await;
    let created = harness.create_agent_with_fixture().await;
    let handle =
        AgentHandle::new(created.agent_handle.clone()).expect("returned handle must be valid");

    harness
        .router
        .dispatch(
            r#"(lang greet-d (greet :target "x" :thread "t-3" :caused-by "sha256:beefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdead"))"#,
        )
        .await;

    let result = timeout(
        Duration::from_millis(250),
        harness.agents.recv(&handle, Some(Duration::from_millis(150))),
    )
    .await
    .expect("outer timeout must not fire before inner");
    assert!(
        matches!(result, Err(hark::daemon::AgentError::RecvTimeout)),
        "expected RecvTimeout, got {result:?}"
    );

    harness.shutdown().await;
}

#[tokio::test]
async fn inbound_happy_path_enqueues_and_appends_to_store() {
    let harness = Harness::start().await;
    let created = harness.create_agent_with_fixture().await;
    let handle =
        AgentHandle::new(created.agent_handle.clone()).expect("returned handle must be valid");

    // Use the core `reply` performative (no shape attached; protocol allows
    // it as a successor of `begin` via `(any greet reply)`). Pipeline accepts;
    // process_inbound must enqueue + append.
    //
    // Note on the deviation from the spec's "valid greet" phrasing: cbcl-rs
    // applies shape rules to the *expanded* form (REQ-223), not the wire
    // form. The fixture's `greet` template `(effect greet-action)` discards
    // keyword params, so `(shape greet (require :target string))` can never
    // be satisfied by ANY wire-level `:target` — it only ever fires as a
    // violation. The happy path therefore exercises a sibling performative
    // (`reply`) whose acceptance proves the registry + per-handle store are
    // consulted on the inbound path.
    let message = r#"(lang greet-d (reply "ok" :thread "t-4" :caused-by "begin"))"#;

    harness.router.dispatch(message).await;

    // Recv must observe the message.
    let received = timeout(
        Duration::from_secs(1),
        harness.agents.recv(&handle, Some(Duration::from_millis(500))),
    )
    .await
    .expect("recv must complete within timeout")
    .expect("recv must succeed");
    assert_eq!(received, message);

    // Store must contain the canonical-hashed inner simple message.
    let expected_hash = canonical_simple_hash(message).expect("hash computation must succeed");
    let stored = harness
        .agents
        .lookup_message(&handle, &expected_hash)
        .await
        .expect("lookup must not error");
    assert!(
        stored.is_some(),
        "inbound happy-path message must be appended to the per-handle store"
    );

    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// Helpers: canonical hash of the innermost simple message (matches the
// daemon's `build_store_entry` / `build_outbound_store_entry` recipe).
// ---------------------------------------------------------------------------

/// Compute the hash the daemon stores: parse the wire frame, take the
/// innermost simple `Message`, re-encode it via `Message -> SExpr` (which
/// normalises e.g. `:caused-by "begin"` to a symbol), canonical-encode,
/// then sha256. Mirrors `build_store_entry` in `src/router.rs` and
/// `build_outbound_store_entry` in `src/local_api.rs`.
fn canonical_simple_hash(message: &str) -> Option<ContentHash> {
    let sexpr = parse(message).ok()?;
    let parsed: Message = parse_message(&sexpr).ok()?;
    let simple = parsed.innermost_simple()?;
    let simple_sexpr: SExpr = simple.into();
    let bytes = canonical_encode(&simple_sexpr);
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Some(ContentHash(format!("sha256:{:x}", hasher.finalize())))
}

// ---------------------------------------------------------------------------
// Harness: a local HTTP daemon + a mock router whose dispatch is driven by
// an explicit `dispatch(frame)` call. The harness exposes the daemon's
// `AgentStore` clone so tests can install dialects and inspect the
// per-handle causal store directly.
// ---------------------------------------------------------------------------

struct Harness {
    record: DiscoveryRecord,
    agents: AgentStore,
    api_task: JoinHandle<Result<(), hark::local_api::LocalApiError>>,
    router: MockRouter,
}

impl Harness {
    async fn start() -> Self {
        let router = MockRouter::start().await;
        let mut config = AppConfig::default();
        config.router.ws_url = Some(router.ws_url());
        config.router.auth_token = Some("shr_test.secret".to_owned());
        let agents = AgentStore::new(AgentStoreConfig::from_config(&config));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("local API should bind");
        let addr = listener.local_addr().expect("local API addr must exist");
        let record = sample_record(addr);
        let task_record = record.clone();
        let task_agents = agents.clone();
        let api_task = tokio::spawn(async move {
            serve_local_api_with_agents(listener, task_record, None, task_agents, config).await
        });
        let harness = Self {
            record,
            agents,
            api_task,
            router,
        };
        harness.wait_until_ready().await;
        harness
    }

    async fn create_agent_with_fixture(&self) -> CreateAgentResponse {
        let created = self.create_agent(&[FIXTURE_NAME]).await;
        // Wait for the daemon to complete the router hello handshake so the
        // dialect_cache_handle resolves cleanly before we try to install.
        self.router.wait_for_hello(Duration::from_secs(1)).await;
        let handle = AgentHandle::new(created.agent_handle.clone())
            .expect("returned handle must be valid");
        let cache = self
            .agents
            .dialect_cache_handle(&handle)
            .await
            .expect("dialect cache must resolve");
        cache
            .try_install(FIXTURE_NAME, FIXTURE_DEFINE)
            .expect("R5-clean fixture must install");
        created
    }

    async fn create_agent(&self, dialects: &[&str]) -> CreateAgentResponse {
        let response = reqwest::Client::new()
            .post(self.url("/v1/agents"))
            .header("authorization", format!("Bearer {}", self.record.token))
            .json(&serde_json::json!({
                "dialects": dialects,
                // r5_runtime's mock router does not answer meta queries; the
                // fixture is installed explicitly via `try_install` after this
                // call. Opt out of auto-install so init does not stall.
                "auto_install_advertised": false,
            }))
            .send()
            .await
            .expect("create-agent request must complete");
        assert!(
            response.status().is_success(),
            "create-agent must succeed, got {}",
            response.status()
        );
        response.json().await.expect("create response must decode")
    }

    async fn post_send(
        &self,
        handle: &str,
        kind: &str,
        message: &str,
    ) -> Result<reqwest::Response, reqwest::Error> {
        reqwest::Client::new()
            .post(self.url(&format!("/v1/agents/{handle}/send")))
            .header("authorization", format!("Bearer {}", self.record.token))
            .json(&serde_json::json!({ "kind": kind, "message": message }))
            .send()
            .await
    }

    async fn shutdown(self) {
        let _ = reqwest::Client::new()
            .post(self.url("/v1/stop"))
            .header("authorization", format!("Bearer {}", self.record.token))
            .send()
            .await;
        // Best-effort: don't fail the test if the task already exited.
        let _ = self.api_task.await;
        self.router.abort();
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.record.addr, path)
    }

    async fn wait_until_ready(&self) {
        for _ in 0..50 {
            let result = reqwest::Client::new()
                .get(self.url("/v1/ping"))
                .header("authorization", format!("Bearer {}", self.record.token))
                .send()
                .await;
            if let Ok(response) = result {
                if response.status().is_success() {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("local API did not become ready");
    }
}

#[derive(Default)]
struct MockRouterState {
    hello_frames: Vec<String>,
    captured_frames: Vec<String>,
    dispatch_sink: Option<oneshot::Sender<DispatchCommand>>,
}

enum DispatchCommand {
    Send(String),
}

#[derive(Clone)]
struct MockRouter {
    addr: SocketAddr,
    shared: Arc<Mutex<MockRouterState>>,
    task: Arc<Mutex<Option<JoinHandle<()>>>>,
}

impl MockRouter {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("mock router must bind");
        let addr = listener.local_addr().expect("mock router addr must exist");
        let shared = Arc::new(Mutex::new(MockRouterState::default()));
        let task_shared = Arc::clone(&shared);
        let task = tokio::spawn(async move {
            let Ok((stream, _peer)) = listener.accept().await else {
                return;
            };
            handle_connection(stream, task_shared).await;
        });
        Self {
            addr,
            shared,
            task: Arc::new(Mutex::new(Some(task))),
        }
    }

    fn ws_url(&self) -> String {
        format!("ws://{}/agent/v1", self.addr)
    }

    async fn wait_for_hello(&self, max: Duration) {
        let deadline = tokio::time::Instant::now() + max;
        while tokio::time::Instant::now() < deadline {
            if !self
                .shared
                .lock()
                .expect("mock state lock")
                .hello_frames
                .is_empty()
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("mock router never received hello");
    }

    async fn dispatch(&self, frame: &str) {
        // Try a few times so the connection has time to install its sender.
        for _ in 0..200 {
            let sender = self
                .shared
                .lock()
                .expect("mock state lock")
                .dispatch_sink
                .take();
            if let Some(sender) = sender {
                sender
                    .send(DispatchCommand::Send(frame.to_owned()))
                    .map_err(|_| ())
                    .expect("dispatch sender must accept");
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("mock router never installed a dispatch sink");
    }

    fn captured_frame(&self) -> Option<String> {
        self.shared
            .lock()
            .expect("mock state lock")
            .captured_frames
            .first()
            .cloned()
    }

    async fn wait_for_captured_frame(&self, max: Duration) {
        let deadline = tokio::time::Instant::now() + max;
        while tokio::time::Instant::now() < deadline {
            if !self
                .shared
                .lock()
                .expect("mock state lock")
                .captured_frames
                .is_empty()
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("mock router never captured a frame");
    }

    fn abort(self) {
        if let Some(task) = self.task.lock().expect("task lock").take() {
            task.abort();
        }
    }
}

async fn handle_connection(stream: tokio::net::TcpStream, shared: Arc<Mutex<MockRouterState>>) {
    let Ok(mut websocket) = accept_async(stream).await else {
        return;
    };
    // Read hello.
    if let Some(Ok(msg)) = websocket.next().await {
        shared
            .lock()
            .expect("mock state lock")
            .hello_frames
            .push(message_to_string(msg));
    }

    // Install a fresh dispatch sink. The harness consumes the sender via
    // `dispatch(...)` and drops the receiver, so the loop below sees an
    // optional next frame for the lifetime of the connection.
    let (tx, mut rx) = oneshot::channel::<DispatchCommand>();
    {
        let mut guard = shared.lock().expect("mock state lock");
        guard.dispatch_sink = Some(tx);
    }

    loop {
        tokio::select! {
            biased;
            // Outbound dispatch from the test to the daemon.
            cmd = &mut rx => {
                match cmd {
                    Ok(DispatchCommand::Send(frame)) => {
                        let _ = websocket
                            .send(WsMessage::Binary(frame.into_bytes().into()))
                            .await;
                        // Single dispatch per connection — re-arm in case a
                        // future test wants another (none do today; keep the
                        // contract simple).
                        let (next_tx, next_rx) = oneshot::channel::<DispatchCommand>();
                        rx = next_rx;
                        shared
                            .lock()
                            .expect("mock state lock")
                            .dispatch_sink = Some(next_tx);
                    }
                    Err(_) => {
                        // Sender dropped — nothing more to dispatch this round.
                        let (next_tx, next_rx) = oneshot::channel::<DispatchCommand>();
                        rx = next_rx;
                        shared
                            .lock()
                            .expect("mock state lock")
                            .dispatch_sink = Some(next_tx);
                    }
                }
            }
            // Inbound from the daemon (capture sends + heartbeats).
            incoming = websocket.next() => {
                match incoming {
                    Some(Ok(WsMessage::Binary(bytes))) => {
                        let text = String::from_utf8_lossy(&bytes).into_owned();
                        // Filter heartbeats — tests assert against work
                        // frames only and shouldn't see the keepalive.
                        if text != r#"(lang cbcl-router (tell @router "heartbeat"))"# {
                            shared
                                .lock()
                                .expect("mock state lock")
                                .captured_frames
                                .push(text);
                        }
                    }
                    Some(Ok(WsMessage::Text(text))) => {
                        shared
                            .lock()
                            .expect("mock state lock")
                            .captured_frames
                            .push(text.to_string());
                    }
                    Some(Ok(_other)) => {}
                    Some(Err(_)) | None => return,
                }
            }
        }
    }
}

fn message_to_string(message: WsMessage) -> String {
    match message {
        WsMessage::Binary(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        WsMessage::Text(text) => text.to_string(),
        other => format!("{other:?}"),
    }
}

async fn error_code(response: reqwest::Response) -> String {
    response
        .json::<ErrorResponse>()
        .await
        .expect("error response must decode")
        .error
        .code
}

async fn error_body(response: reqwest::Response) -> hark::local_api::ErrorBody {
    response
        .json::<ErrorResponse>()
        .await
        .expect("error response must decode")
        .error
}

fn sample_record(addr: SocketAddr) -> DiscoveryRecord {
    DiscoveryRecord {
        pid: 12345,
        addr,
        token: "r5-runtime-integration-token".to_owned(),
        started_at: OffsetDateTime::from_unix_timestamp(1_800_000_000)
            .expect("timestamp must be valid"),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        api_version: LOCAL_API_VERSION,
    }
}
