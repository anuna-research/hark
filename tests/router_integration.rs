use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use cbcl_router_client::{
    config::AppConfig,
    constants::LOCAL_API_VERSION,
    daemon::{AgentStore, AgentStoreConfig, DiscoveryRecord},
    local_api::{CreateAgentResponse, ErrorResponse, RecvResponse, serve_local_api_with_agents},
};
use futures_util::{SinkExt, StreamExt};
use time::OffsetDateTime;
use tokio::{net::TcpListener, task::JoinHandle, time::Duration};
use tokio_tungstenite::{
    accept_hdr_async,
    tungstenite::{
        Message,
        handshake::server::{ErrorResponse as WsErrorResponse, Request, Response},
        http::StatusCode as WsStatusCode,
        protocol::{CloseFrame, frame::coding::CloseCode},
    },
};

#[tokio::test]
async fn router_integration_success_sends_auth_and_hello_then_enqueues_dispatch() {
    let router = MockRouter::start(RouterBehavior::SendDispatch).await;
    let local = LocalApi::start(router.ws_url()).await;

    let created = local
        .create_agent(&["code:edit", "code:test"], &["elf"])
        .await
        .expect("agent should be created");

    assert_eq!(created.capabilities, ["code:edit", "code:test"]);
    assert_eq!(created.dialects, ["elf"]);
    assert_eq!(created.state, "connected");

    router.wait_for_hello(Duration::from_secs(1)).await;
    assert_eq!(
        router.auth_header(),
        Some("Bearer shr_test.secret".to_owned())
    );
    let hello = router.hello_frame().expect("hello should be captured");
    assert!(hello.contains(":agent-id"));
    assert!(hello.contains(&created.router_agent_id));
    assert!(hello.contains(":capabilities (\"code:edit\" \"code:test\")"));
    assert!(hello.contains(":dialects (\"elf\")"));

    let received = local.recv(&created.agent_handle).await;
    assert_eq!(
        received.message,
        "(lang elf (ask @router \"work\" :thread \"rcp-1\"))"
    );

    router.wait().await;
    local.stop().await;
}

#[tokio::test]
async fn router_integration_rejects_missing_router_config_before_connecting() {
    let local = LocalApi::start_with_config(AppConfig::default()).await;

    let response = local
        .post_agent(&["code:edit"], &[])
        .await
        .expect("request should complete");

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    assert_eq!(error_code(response).await, "missing_router_ws_url");
    local.stop().await;
}

#[tokio::test]
async fn router_integration_maps_invalid_and_missing_router_config() {
    let mut invalid_url = AppConfig::default();
    invalid_url.router.ws_url = Some("https://router.example/agent/v1".to_owned());
    invalid_url.router.auth_token = Some("shr_test.secret".to_owned());
    let local = LocalApi::start_with_config(invalid_url).await;
    let response = local
        .post_agent(&["code:edit"], &[])
        .await
        .expect("request should complete");
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    assert_eq!(error_code(response).await, "invalid_router_ws_url");
    local.stop().await;

    let mut missing_token = AppConfig::default();
    missing_token.router.ws_url = Some("ws://127.0.0.1:9/agent/v1".to_owned());
    let local = LocalApi::start_with_config(missing_token).await;
    let response = local
        .post_agent(&["code:edit"], &[])
        .await
        .expect("request should complete");
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    assert_eq!(error_code(response).await, "missing_router_auth_token");
    local.stop().await;
}

#[tokio::test]
async fn router_integration_maps_router_auth_rejection() {
    let router = MockRouter::start(RouterBehavior::RejectAuth).await;
    let local = LocalApi::start(router.ws_url()).await;

    let response = local
        .post_agent(&["code:edit"], &[])
        .await
        .expect("request should complete");

    assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(error_code(response).await, "router_auth_rejected");
    router.wait().await;
    local.stop().await;
}

#[tokio::test]
async fn router_integration_maps_router_connection_failure() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("temporary listener should bind");
    let addr = listener.local_addr().expect("temporary addr should exist");
    drop(listener);
    let local = LocalApi::start(format!("ws://{addr}/agent/v1")).await;

    let response = local
        .post_agent(&["code:edit"], &[])
        .await
        .expect("request should complete");

    assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(error_code(response).await, "router_connection_failed");
    local.stop().await;
}

#[tokio::test]
async fn router_integration_marks_handle_unhealthy_on_router_close() {
    let router = MockRouter::start(RouterBehavior::CloseAfterHello).await;
    let local = LocalApi::start(router.ws_url()).await;
    let created = local
        .create_agent(&["code:edit"], &[])
        .await
        .expect("agent should be created");

    router.wait().await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let status = local.agents().await;
    let agent = status
        .agents
        .iter()
        .find(|agent| agent.agent_handle == created.agent_handle)
        .expect("agent should exist");
    assert_eq!(agent.state, "unhealthy");
    assert_eq!(agent.unhealthy_reason.as_deref(), Some("router_closed"));
    assert!(
        agent
            .unhealthy_detail
            .as_deref()
            .unwrap_or("")
            .contains("code=Normal")
    );

    local.stop().await;
}

#[tokio::test]
async fn router_integration_marks_handle_unhealthy_on_router_error() {
    let router = MockRouter::start(RouterBehavior::SendError).await;
    let local = LocalApi::start(router.ws_url()).await;
    let created = local
        .create_agent(&["code:edit"], &[])
        .await
        .expect("agent should be created");

    router.wait().await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let status = local.agents().await;
    let agent = status
        .agents
        .iter()
        .find(|agent| agent.agent_handle == created.agent_handle)
        .expect("agent should exist");
    assert_eq!(agent.state, "unhealthy");
    assert_eq!(agent.unhealthy_reason.as_deref(), Some("router_error"));
    assert!(
        agent
            .unhealthy_detail
            .as_deref()
            .unwrap_or("")
            .contains("bad hello")
    );

    local.stop().await;
}

#[tokio::test]
async fn router_integration_rejects_duplicate_capability_before_router_connect() {
    let router = MockRouter::start(RouterBehavior::SendDispatch).await;
    let local = LocalApi::start(router.ws_url()).await;

    let response = local
        .post_agent(&["code:edit", "code:edit"], &[])
        .await
        .expect("request should complete");

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    assert_eq!(error_code(response).await, "duplicate_capability");
    assert!(
        router
            .wait_timeout(Duration::from_millis(100))
            .await
            .is_none()
    );

    local.stop().await;
}

#[tokio::test]
async fn router_integration_send_writes_binary_frame_to_router() {
    let router = MockRouter::start(RouterBehavior::CaptureSend).await;
    let local = LocalApi::start(router.ws_url()).await;
    let created = local
        .create_agent(&["code:edit"], &["elf"])
        .await
        .expect("agent should be created");

    let response = local
        .post_send(
            &created.agent_handle,
            "reply",
            r#"(lang elf (reply "done" :thread "rcp-1"))"#,
        )
        .await
        .expect("send request should complete");

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    router.wait().await;
    assert_eq!(
        router.sent_frame(),
        Some(r#"(lang elf (reply "done" :thread "rcp-1"))"#.to_owned())
    );
    local.stop().await;
}

#[tokio::test]
async fn router_integration_send_rejects_validation_errors_without_forwarding() {
    let router = MockRouter::start(RouterBehavior::CaptureSend).await;
    let local = LocalApi::start(router.ws_url()).await;
    let created = local
        .create_agent(&["code:edit"], &[])
        .await
        .expect("agent should be created");
    router.wait_for_hello(Duration::from_secs(1)).await;

    let response = local
        .post_send(
            &created.agent_handle,
            "reply",
            r#"(error "failed" :thread "rcp-1")"#,
        )
        .await
        .expect("send request should complete");

    assert_eq!(response.status(), reqwest::StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(error_code(response).await, "message_kind_mismatch");
    assert!(router.sent_frame().is_none());
    router.abort();
    local.stop().await;
}

#[tokio::test]
async fn router_integration_sends_heartbeat_on_idle_connection() {
    let router = MockRouter::start(RouterBehavior::CaptureHeartbeat).await;
    let local = LocalApi::start(router.ws_url()).await;
    let _created = local
        .create_agent(&["code:edit"], &[])
        .await
        .expect("agent should be created");

    router.wait_for_hello(Duration::from_secs(1)).await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(31)).await;

    router.wait().await;
    assert_eq!(
        router.sent_frame(),
        Some(r#"(lang cbcl-router (tell @router "heartbeat"))"#.to_owned())
    );
    local.stop().await;
}

#[tokio::test]
async fn router_integration_sends_heartbeat_for_each_active_connection() {
    let router = MockRouter::start_accepting(RouterBehavior::CaptureHeartbeat, 2).await;
    let local = LocalApi::start(router.ws_url()).await;
    let _first = local
        .create_agent(&["code:edit"], &[])
        .await
        .expect("first agent should be created");
    let _second = local
        .create_agent(&["code:test"], &[])
        .await
        .expect("second agent should be created");

    router.wait_for_hellos(2, Duration::from_secs(1)).await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(31)).await;

    router.wait().await;
    assert_eq!(
        router.sent_frames(),
        vec![
            r#"(lang cbcl-router (tell @router "heartbeat"))"#.to_owned(),
            r#"(lang cbcl-router (tell @router "heartbeat"))"#.to_owned(),
        ]
    );
    local.stop().await;
}

#[tokio::test]
async fn router_integration_send_rejects_unknown_handle() {
    let router = MockRouter::start(RouterBehavior::CaptureSend).await;
    let local = LocalApi::start(router.ws_url()).await;

    let response = local
        .post_send(
            "0123456789ABCDEFGHJKMNPQRS",
            "reply",
            r#"(reply "done" :thread "rcp-1")"#,
        )
        .await
        .expect("send request should complete");

    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
    assert_eq!(error_code(response).await, "unknown_agent_handle");
    router.abort();
    local.stop().await;
}

#[derive(Debug, Clone, Copy)]
enum RouterBehavior {
    SendDispatch,
    CaptureSend,
    CaptureHeartbeat,
    RejectAuth,
    CloseAfterHello,
    SendError,
}

#[derive(Clone)]
struct MockRouter {
    addr: SocketAddr,
    shared: Arc<Mutex<MockRouterState>>,
    task: Arc<Mutex<Option<JoinHandle<()>>>>,
}

#[derive(Default)]
struct MockRouterState {
    auth_headers: Vec<String>,
    hello_frames: Vec<String>,
    sent_frames: Vec<String>,
}

impl MockRouter {
    async fn start(behavior: RouterBehavior) -> Self {
        Self::start_accepting(behavior, 1).await
    }

    async fn start_accepting(behavior: RouterBehavior, connection_count: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("router should bind");
        let addr = listener.local_addr().expect("router addr should exist");
        let shared = Arc::new(Mutex::new(MockRouterState::default()));
        let task_shared = Arc::clone(&shared);
        let task = tokio::spawn(async move {
            let mut handlers = Vec::new();
            for _ in 0..connection_count {
                let Ok((stream, _peer)) = listener.accept().await else {
                    return;
                };
                let connection_shared = Arc::clone(&task_shared);
                handlers.push(tokio::spawn(async move {
                    handle_mock_connection(stream, connection_shared, behavior).await;
                }));
            }
            for handler in handlers {
                let _ = handler.await;
            }
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

    fn auth_header(&self) -> Option<String> {
        self.shared
            .lock()
            .expect("mock state should lock")
            .auth_headers
            .first()
            .cloned()
    }

    fn hello_frame(&self) -> Option<String> {
        self.shared
            .lock()
            .expect("mock state should lock")
            .hello_frames
            .first()
            .cloned()
    }

    fn sent_frame(&self) -> Option<String> {
        self.shared
            .lock()
            .expect("mock state should lock")
            .sent_frames
            .first()
            .cloned()
    }

    fn sent_frames(&self) -> Vec<String> {
        let mut frames = self
            .shared
            .lock()
            .expect("mock state should lock")
            .sent_frames
            .clone();
        frames.sort();
        frames
    }

    async fn wait_for_hello(&self, timeout: Duration) {
        let deadline = tokio::time::Instant::now() + timeout;
        while tokio::time::Instant::now() < deadline {
            if self.hello_frame().is_some() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("mock router did not receive hello");
    }

    async fn wait_for_hellos(&self, count: usize, timeout: Duration) {
        let deadline = tokio::time::Instant::now() + timeout;
        while tokio::time::Instant::now() < deadline {
            if self
                .shared
                .lock()
                .expect("mock state should lock")
                .hello_frames
                .len()
                >= count
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("mock router did not receive {count} hellos");
    }

    async fn wait(&self) {
        let task = self.task.lock().expect("task should lock").take();
        if let Some(task) = task {
            task.await.expect("router task should not panic");
        }
    }

    fn abort(&self) {
        if let Some(task) = self.task.lock().expect("task should lock").take() {
            task.abort();
        }
    }

    async fn wait_timeout(&self, timeout: Duration) -> Option<()> {
        let mut task = self.task.lock().expect("task should lock").take()?;
        match tokio::time::timeout(timeout, &mut task).await {
            Ok(result) => {
                result.expect("router task should not panic");
                Some(())
            }
            Err(_) => {
                task.abort();
                None
            }
        }
    }
}

async fn handle_mock_connection(
    stream: tokio::net::TcpStream,
    shared: Arc<Mutex<MockRouterState>>,
    behavior: RouterBehavior,
) {
    let callback_shared = Arc::clone(&shared);
    let callback = move |request: &Request, response: Response| {
        if let Some(auth_header) = request
            .headers()
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned)
        {
            callback_shared
                .lock()
                .expect("mock state should lock")
                .auth_headers
                .push(auth_header);
        }
        if matches!(behavior, RouterBehavior::RejectAuth) {
            let mut response = WsErrorResponse::new(Some("unauthorized".to_owned()));
            *response.status_mut() = WsStatusCode::UNAUTHORIZED;
            return Err(response);
        }
        Ok(response)
    };
    let Ok(mut websocket) = accept_hdr_async(stream, callback).await else {
        return;
    };
    if let Some(Ok(message)) = websocket.next().await {
        let hello = message_to_string(message);
        shared
            .lock()
            .expect("mock state should lock")
            .hello_frames
            .push(hello);
    }

    match behavior {
        RouterBehavior::SendDispatch => {
            let _ = websocket
                .send(Message::Binary(
                    b"(lang elf (ask @router \"work\" :thread \"rcp-1\"))"
                        .to_vec()
                        .into(),
                ))
                .await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        RouterBehavior::CaptureSend | RouterBehavior::CaptureHeartbeat => {
            if let Some(Ok(message)) = websocket.next().await {
                shared
                    .lock()
                    .expect("mock state should lock")
                    .sent_frames
                    .push(message_to_string(message));
            }
        }
        RouterBehavior::CloseAfterHello => {
            let _ = websocket
                .close(Some(CloseFrame {
                    code: CloseCode::Normal,
                    reason: "idle timeout".into(),
                }))
                .await;
        }
        RouterBehavior::SendError => {
            let _ = websocket
                .send(Message::Binary(
                    b"(lang cbcl-router (error @router \"bad hello\"))"
                        .to_vec()
                        .into(),
                ))
                .await;
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        RouterBehavior::RejectAuth => {}
    }
}

struct LocalApi {
    record: DiscoveryRecord,
    task: JoinHandle<Result<(), cbcl_router_client::local_api::LocalApiError>>,
}

impl LocalApi {
    async fn start(router_ws_url: String) -> Self {
        let mut config = AppConfig::default();
        config.router.ws_url = Some(router_ws_url);
        config.router.auth_token = Some("shr_test.secret".to_owned());
        Self::start_with_config(config).await
    }

    async fn start_with_config(config: AppConfig) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("local api should bind");
        let addr = listener.local_addr().expect("local api addr should exist");
        let record = sample_record(addr);
        let task_record = record.clone();
        let store = AgentStore::new(AgentStoreConfig::from_config(&config));
        let task = tokio::spawn(async move {
            serve_local_api_with_agents(listener, task_record, None, store, config).await
        });
        let api = Self { record, task };
        api.wait_until_ready().await;
        api
    }

    async fn post_agent(
        &self,
        capabilities: &[&str],
        dialects: &[&str],
    ) -> Result<reqwest::Response, reqwest::Error> {
        reqwest::Client::new()
            .post(self.url("/v1/agents"))
            .header("authorization", format!("Bearer {}", self.record.token))
            .json(&serde_json::json!({
                "capabilities": capabilities,
                "dialects": dialects,
            }))
            .send()
            .await
    }

    async fn create_agent(
        &self,
        capabilities: &[&str],
        dialects: &[&str],
    ) -> Option<CreateAgentResponse> {
        let response = self
            .post_agent(capabilities, dialects)
            .await
            .expect("request should complete");
        if !response.status().is_success() {
            return None;
        }
        Some(
            response
                .json()
                .await
                .expect("create response should decode"),
        )
    }

    async fn recv(&self, handle: &str) -> RecvResponse {
        reqwest::Client::new()
            .get(self.url(&format!("/v1/agents/{handle}/recv?timeout_ms=1000")))
            .header("authorization", format!("Bearer {}", self.record.token))
            .send()
            .await
            .expect("recv request should complete")
            .json()
            .await
            .expect("recv response should decode")
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
            .json(&serde_json::json!({
                "kind": kind,
                "message": message,
            }))
            .send()
            .await
    }

    async fn agents(&self) -> cbcl_router_client::local_api::AgentsResponse {
        reqwest::Client::new()
            .get(self.url("/v1/agents"))
            .header("authorization", format!("Bearer {}", self.record.token))
            .send()
            .await
            .expect("status request should complete")
            .json()
            .await
            .expect("status response should decode")
    }

    async fn stop(self) {
        let _ = reqwest::Client::new()
            .post(self.url("/v1/stop"))
            .header("authorization", format!("Bearer {}", self.record.token))
            .send()
            .await;
        self.task
            .await
            .expect("local API task should not panic")
            .expect("local API should stop cleanly");
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.record.addr, path)
    }

    async fn wait_until_ready(&self) {
        for _ in 0..20 {
            let Ok(response) = reqwest::Client::new()
                .get(self.url("/v1/ping"))
                .header("authorization", format!("Bearer {}", self.record.token))
                .send()
                .await
            else {
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            };
            if response.status().is_success() {
                return;
            }
        }
        panic!("local API did not become ready");
    }
}

fn message_to_string(message: Message) -> String {
    match message {
        Message::Binary(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Message::Text(text) => text.to_string(),
        other => format!("{other:?}"),
    }
}

async fn error_code(response: reqwest::Response) -> String {
    response
        .json::<ErrorResponse>()
        .await
        .expect("error response should decode")
        .error
        .code
}

fn sample_record(addr: SocketAddr) -> DiscoveryRecord {
    DiscoveryRecord {
        pid: 12345,
        addr,
        token: "local-router-integration-token".to_owned(),
        started_at: OffsetDateTime::from_unix_timestamp(1_800_000_000)
            .expect("timestamp should be valid"),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        api_version: LOCAL_API_VERSION,
    }
}
