use std::{
    fmt,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use reqwest::header::{AUTHORIZATION, HeaderValue};
use serde::{Deserialize, Serialize};
use tokio::{net::TcpListener, sync::oneshot};

use crate::{
    constants::{LOCAL_API_VERSION, MAX_RECV_TIMEOUT_MS},
    daemon::{
        AgentError, AgentHandle, AgentStore, AgentStoreConfig, DiscoveryRecord,
        authenticated_headers,
    },
};

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct PingResponse {
    pub ok: bool,
    pub version: String,
    pub api_version: u16,
}

impl PingResponse {
    pub fn current() -> Self {
        Self {
            ok: true,
            version: env!("CARGO_PKG_VERSION").to_owned(),
            api_version: LOCAL_API_VERSION,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct StopResponse {
    pub ok: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct RecvResponse {
    pub agent_handle: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct CloseResponse {
    pub ok: bool,
    pub agent_handle: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct AgentsResponse {
    pub daemon: DaemonStatus,
    pub agents: Vec<AgentStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct DaemonStatus {
    pub pid: u32,
    pub addr: SocketAddr,
    pub version: String,
    pub api_version: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct AgentStatus {
    pub agent_handle: String,
    pub router_agent_id: String,
    pub capabilities: Vec<String>,
    pub dialects: Vec<String>,
    pub state: String,
    pub queued_messages: usize,
    pub queued_bytes: usize,
    pub unhealthy_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unhealthy_detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct ErrorResponse {
    pub error: ErrorBody,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

#[derive(Clone)]
pub struct LocalApiClient {
    http: reqwest::Client,
    base_url: String,
    auth_header: HeaderValue,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ClientPingError {
    AuthFailure,
    ApiIncompatible {
        daemon_version: Option<String>,
        daemon_api_version: Option<u16>,
        cli_api_version: u16,
    },
    RequestFailed(String),
    UnexpectedStatus(StatusCode),
    DecodeFailed(String),
}

#[derive(Debug, thiserror::Error)]
pub enum LocalApiError {
    #[error("local API server error: {0}")]
    Server(#[from] std::io::Error),
}

#[derive(Clone)]
struct AppState {
    record: Arc<DiscoveryRecord>,
    stop: Arc<StopState>,
    agents: AgentStore,
}

struct StopState {
    discovery_file: Option<PathBuf>,
    stopping: AtomicBool,
    shutdown_tx: Mutex<Option<oneshot::Sender<()>>>,
}

impl LocalApiClient {
    pub fn from_discovery(record: &DiscoveryRecord) -> Result<Self, crate::daemon::DiscoveryError> {
        let headers = authenticated_headers(record)?;
        let auth_header = headers
            .get(AUTHORIZATION)
            .expect("authenticated_headers should set authorization")
            .clone();

        Ok(Self {
            http: reqwest::Client::new(),
            base_url: format!("http://{}", record.addr),
            auth_header,
        })
    }

    pub async fn ping(&self) -> Result<PingResponse, ClientPingError> {
        let response = self
            .http
            .get(self.url("/v1/ping"))
            .header(AUTHORIZATION, self.auth_header.clone())
            .send()
            .await
            .map_err(|error| ClientPingError::RequestFailed(error.to_string()))?;

        if response.status() == StatusCode::UNAUTHORIZED {
            return Err(ClientPingError::AuthFailure);
        }

        if !response.status().is_success() {
            return Err(ClientPingError::UnexpectedStatus(response.status()));
        }

        let ping = response
            .json::<PingResponse>()
            .await
            .map_err(|error| ClientPingError::DecodeFailed(error.to_string()))?;

        self.validate_ping(ping)
    }

    pub async fn agents(&self) -> Result<AgentsResponse, ClientPingError> {
        let response = self
            .http
            .get(self.url("/v1/agents"))
            .header(AUTHORIZATION, self.auth_header.clone())
            .send()
            .await
            .map_err(|error| ClientPingError::RequestFailed(error.to_string()))?;

        if response.status() == StatusCode::UNAUTHORIZED {
            return Err(ClientPingError::AuthFailure);
        }

        if !response.status().is_success() {
            return Err(ClientPingError::UnexpectedStatus(response.status()));
        }

        response
            .json::<AgentsResponse>()
            .await
            .map_err(|error| ClientPingError::DecodeFailed(error.to_string()))
    }

    pub async fn stop(&self) -> Result<StopResponse, ClientPingError> {
        let response = self
            .http
            .post(self.url("/v1/stop"))
            .header(AUTHORIZATION, self.auth_header.clone())
            .send()
            .await
            .map_err(|error| ClientPingError::RequestFailed(error.to_string()))?;

        if response.status() == StatusCode::UNAUTHORIZED {
            return Err(ClientPingError::AuthFailure);
        }

        if !response.status().is_success() {
            return Err(ClientPingError::UnexpectedStatus(response.status()));
        }

        response
            .json::<StopResponse>()
            .await
            .map_err(|error| ClientPingError::DecodeFailed(error.to_string()))
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    fn validate_ping(&self, ping: PingResponse) -> Result<PingResponse, ClientPingError> {
        if ping.api_version != LOCAL_API_VERSION {
            return Err(ClientPingError::ApiIncompatible {
                daemon_version: Some(ping.version),
                daemon_api_version: Some(ping.api_version),
                cli_api_version: LOCAL_API_VERSION,
            });
        }

        Ok(ping)
    }
}

impl fmt::Display for ClientPingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthFailure => write!(formatter, "local daemon authentication failed"),
            Self::ApiIncompatible {
                daemon_version,
                daemon_api_version,
                cli_api_version,
            } => write!(
                formatter,
                "daemon_api_incompatible: CLI API version {cli_api_version}, daemon API version {:?}, daemon version {:?}",
                daemon_api_version, daemon_version
            ),
            Self::RequestFailed(error) => write!(formatter, "request failed: {error}"),
            Self::UnexpectedStatus(status) => write!(formatter, "unexpected HTTP status: {status}"),
            Self::DecodeFailed(error) => write!(formatter, "failed to decode response: {error}"),
        }
    }
}

pub async fn serve_local_api(
    listener: TcpListener,
    record: DiscoveryRecord,
    discovery_file: Option<PathBuf>,
) -> Result<(), LocalApiError> {
    serve_local_api_with_agents(
        listener,
        record,
        discovery_file,
        AgentStore::new(AgentStoreConfig {
            agent_id_prefix: crate::constants::DEFAULT_AGENT_ID_PREFIX.to_owned(),
            max_messages_per_handle: crate::constants::DEFAULT_MAX_MESSAGES_PER_HANDLE,
            max_bytes_per_handle: crate::constants::DEFAULT_MAX_BYTES_PER_HANDLE,
        }),
    )
    .await
}

pub async fn serve_local_api_with_agents(
    listener: TcpListener,
    record: DiscoveryRecord,
    discovery_file: Option<PathBuf>,
    agents: AgentStore,
) -> Result<(), LocalApiError> {
    if !listener.local_addr()?.ip().is_loopback() {
        return Err(LocalApiError::Server(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "local API listener must be bound to loopback",
        )));
    }

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let state = AppState {
        record: Arc::new(record),
        agents,
        stop: Arc::new(StopState {
            discovery_file,
            stopping: AtomicBool::new(false),
            shutdown_tx: Mutex::new(Some(shutdown_tx)),
        }),
    };
    let app = router(state);

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = shutdown_rx.await;
        })
        .await?;

    Ok(())
}

fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/ping", get(ping))
        .route("/v1/agents", get(agents))
        .route("/v1/agents/{handle}/recv", get(recv))
        .route("/v1/agents/{handle}", delete(close_agent))
        .route("/v1/stop", post(stop))
        .with_state(state)
}

async fn ping(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<PingResponse>, ApiError> {
    authorize(&state, &headers)?;
    reject_if_stopping(&state)?;
    Ok(Json(PingResponse::current()))
}

async fn agents(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<AgentsResponse>, ApiError> {
    authorize(&state, &headers)?;
    reject_if_stopping(&state)?;
    let agents = state
        .agents
        .status_snapshots()
        .await
        .into_iter()
        .map(|snapshot| AgentStatus {
            agent_handle: snapshot.agent_handle,
            router_agent_id: snapshot.router_agent_id,
            capabilities: snapshot.capabilities,
            dialects: snapshot.dialects,
            state: snapshot.state.as_str().to_owned(),
            queued_messages: snapshot.queued_messages,
            queued_bytes: snapshot.queued_bytes,
            unhealthy_reason: snapshot.unhealthy_reason,
            unhealthy_detail: snapshot.unhealthy_detail,
        })
        .collect();
    Ok(Json(AgentsResponse {
        daemon: DaemonStatus {
            pid: state.record.pid,
            addr: state.record.addr,
            version: state.record.version.clone(),
            api_version: state.record.api_version,
        },
        agents,
    }))
}

#[derive(Debug, Deserialize)]
struct RecvQuery {
    timeout_ms: Option<u64>,
}

async fn recv(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(handle): Path<String>,
    Query(query): Query<RecvQuery>,
) -> Result<Json<RecvResponse>, ApiError> {
    authorize(&state, &headers)?;
    reject_if_stopping(&state)?;
    let handle = parse_handle(handle)?;
    let timeout = match query.timeout_ms {
        Some(0) => {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "malformed_request",
                "timeout_ms must be positive",
                None,
            ));
        }
        Some(value) if value > MAX_RECV_TIMEOUT_MS => {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "malformed_request",
                "timeout_ms exceeds maximum",
                None,
            ));
        }
        Some(value) => Some(std::time::Duration::from_millis(value)),
        None => None,
    };
    let message = state
        .agents
        .recv(&handle, timeout)
        .await
        .map_err(agent_error_to_api)?;
    Ok(Json(RecvResponse {
        agent_handle: handle.as_str().to_owned(),
        message,
    }))
}

async fn close_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(handle): Path<String>,
) -> Result<Json<CloseResponse>, ApiError> {
    authorize(&state, &headers)?;
    reject_if_stopping(&state)?;
    let handle = parse_handle(handle)?;
    state
        .agents
        .close(&handle)
        .await
        .map_err(agent_error_to_api)?;
    Ok(Json(CloseResponse {
        ok: true,
        agent_handle: handle.as_str().to_owned(),
    }))
}

async fn stop(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<StopResponse>, ApiError> {
    authorize(&state, &headers)?;

    if !state.stop.stopping.swap(true, Ordering::SeqCst) {
        if let Some(discovery_file) = &state.stop.discovery_file {
            match std::fs::remove_file(discovery_file) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(ApiError::internal(error.to_string())),
            }
        }

        if let Some(shutdown_tx) = state
            .stop
            .shutdown_tx
            .lock()
            .expect("shutdown mutex should not be poisoned")
            .take()
        {
            let _ = shutdown_tx.send(());
        }
    }

    Ok(Json(StopResponse { ok: true }))
}

fn authorize(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    let Some(value) = headers.get(AUTHORIZATION) else {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "missing_daemon_token",
            "local authorization header is absent",
            None,
        ));
    };

    let expected = format!("Bearer {}", state.record.token);
    if value.as_bytes() != expected.as_bytes() {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "invalid_daemon_token",
            "local authorization failed",
            None,
        ));
    }

    Ok(())
}

fn reject_if_stopping(state: &AppState) -> Result<(), ApiError> {
    if state.stop.stopping.load(Ordering::SeqCst) {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "daemon_stopping",
            "daemon is shutting down",
            None,
        ));
    }

    Ok(())
}

fn parse_handle(handle: String) -> Result<AgentHandle, ApiError> {
    AgentHandle::new(handle).map_err(agent_error_to_api)
}

fn agent_error_to_api(error: AgentError) -> ApiError {
    match error {
        AgentError::MalformedHandle => ApiError::new(
            StatusCode::BAD_REQUEST,
            "malformed_agent_handle",
            "agent handle is malformed",
            None,
        ),
        AgentError::UnknownHandle => ApiError::new(
            StatusCode::NOT_FOUND,
            "unknown_agent_handle",
            "agent handle is not active",
            Some("run `cbcl-router-client daemon status` to list active handles".to_owned()),
        ),
        AgentError::Unhealthy { reason, detail } => ApiError::new(
            StatusCode::CONFLICT,
            "agent_handle_unhealthy",
            format!("agent handle is unhealthy: {reason}"),
            detail,
        ),
        AgentError::RecvAlreadyWaiting => ApiError::new(
            StatusCode::CONFLICT,
            "recv_already_waiting",
            "a blocking receive is already waiting for this handle",
            None,
        ),
        AgentError::RecvTimeout => ApiError::new(
            StatusCode::REQUEST_TIMEOUT,
            "recv_timeout",
            "blocking receive timed out",
            None,
        ),
        AgentError::QueueOverflow => ApiError::new(
            StatusCode::CONFLICT,
            "agent_handle_unhealthy",
            "agent queue overflowed",
            None,
        ),
        AgentError::MissingCapability => ApiError::new(
            StatusCode::BAD_REQUEST,
            "missing_capability",
            "agent creation requires at least one capability",
            None,
        ),
        AgentError::DuplicateCapability => ApiError::new(
            StatusCode::BAD_REQUEST,
            "duplicate_capability",
            "agent creation request repeats a capability",
            None,
        ),
        AgentError::DuplicateDialect => ApiError::new(
            StatusCode::BAD_REQUEST,
            "duplicate_dialect",
            "agent creation request repeats a dialect",
            None,
        ),
        AgentError::InvalidCapability(message) => {
            ApiError::new(StatusCode::BAD_REQUEST, "invalid_capability", message, None)
        }
        AgentError::InvalidDialect(message) => {
            ApiError::new(StatusCode::BAD_REQUEST, "invalid_dialect", message, None)
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
    hint: Option<String>,
}

impl ApiError {
    fn new(
        status: StatusCode,
        code: &'static str,
        message: impl Into<String>,
        hint: Option<String>,
    ) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            hint,
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            message,
            None,
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorResponse {
                error: ErrorBody {
                    code: self.code.to_owned(),
                    message: self.message,
                    hint: self.hint,
                },
            }),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, path::PathBuf};

    use reqwest::StatusCode;
    use tempfile::TempDir;
    use time::OffsetDateTime;
    use tokio::{net::TcpListener, task::JoinHandle, time::Duration};

    use super::{
        AgentsResponse, ClientPingError, ErrorResponse, LocalApiClient, PingResponse,
        serve_local_api_with_agents,
    };
    use crate::{
        constants::LOCAL_API_VERSION,
        daemon::{AgentHandle, AgentStore, AgentStoreConfig, DiscoveryRecord},
    };

    #[tokio::test]
    async fn ping_requires_authorization() {
        let server = TestServer::start(None).await;

        let response = reqwest::Client::new()
            .get(server.url("/v1/ping"))
            .send()
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = response
            .json::<ErrorResponse>()
            .await
            .expect("error response should decode");
        assert_eq!(body.error.code, "missing_daemon_token");

        server.stop().await;
    }

    #[tokio::test]
    async fn rejects_invalid_authorization() {
        let server = TestServer::start(None).await;

        let response = reqwest::Client::new()
            .get(server.url("/v1/ping"))
            .header(reqwest::header::AUTHORIZATION, "Bearer wrong-token")
            .send()
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = response
            .json::<ErrorResponse>()
            .await
            .expect("error response should decode");
        assert_eq!(body.error.code, "invalid_daemon_token");

        server.stop().await;
    }

    #[tokio::test]
    async fn ping_succeeds_with_valid_authorization() {
        let server = TestServer::start(None).await;

        let ping = server.client().ping().await.expect("ping should succeed");

        assert_eq!(ping, PingResponse::current());

        server.stop().await;
    }

    #[tokio::test]
    async fn agents_status_returns_empty_skeleton() {
        let server = TestServer::start(None).await;

        let status = server
            .client()
            .agents()
            .await
            .expect("agents should succeed");

        assert_eq!(
            status,
            AgentsResponse {
                daemon: super::DaemonStatus {
                    pid: server.record.pid,
                    addr: server.record.addr,
                    version: server.record.version.clone(),
                    api_version: server.record.api_version,
                },
                agents: Vec::new(),
            }
        );

        server.stop().await;
    }

    #[tokio::test]
    async fn stop_removes_discovery_file_and_stops_server() {
        let temp_dir = TempDir::new().expect("temp dir should be created");
        let discovery_file = temp_dir.path().join("daemon.json");
        std::fs::write(&discovery_file, "{}").expect("discovery should be written");
        let server = TestServer::start(Some(discovery_file.clone())).await;
        let client = server.client();

        let stop = client.stop().await.expect("stop should succeed");

        assert!(stop.ok);
        server.await_stopped().await;
        assert!(!discovery_file.exists());

        let error = client
            .ping()
            .await
            .expect_err("ping should fail after shutdown");
        assert!(matches!(error, ClientPingError::RequestFailed(_)));
    }

    #[tokio::test]
    async fn client_reports_api_incompatibility() {
        let server = TestServer::start(None).await;
        let client = server.client();

        let error = client
            .validate_ping(PingResponse {
                ok: true,
                version: "9.9.9".to_owned(),
                api_version: LOCAL_API_VERSION + 1,
            })
            .expect_err("incompatible ping should fail");

        assert_eq!(
            error,
            ClientPingError::ApiIncompatible {
                daemon_version: Some("9.9.9".to_owned()),
                daemon_api_version: Some(LOCAL_API_VERSION + 1),
                cli_api_version: LOCAL_API_VERSION,
            }
        );

        server.stop().await;
    }

    #[tokio::test]
    async fn recv_returns_queued_message() {
        let store = agent_store();
        let handle = handle();
        store
            .insert_connected(handle.clone(), vec!["code:edit".to_owned()], vec![])
            .await
            .expect("agent should insert");
        store
            .enqueue_inbound(&handle, "(ask @router \"work\")".to_owned())
            .await
            .expect("message should enqueue");
        let server = TestServer::start_with_store(None, store).await;

        let response = reqwest::Client::new()
            .get(server.url(&format!("/v1/agents/{}/recv", handle.as_str())))
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {}", server.record.token),
            )
            .send()
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        let body = response
            .json::<super::RecvResponse>()
            .await
            .expect("response should decode");
        assert_eq!(body.agent_handle, handle.as_str());
        assert_eq!(body.message, "(ask @router \"work\")");

        server.stop().await;
    }

    #[tokio::test]
    async fn recv_rejects_malformed_unknown_and_timeout() {
        let store = agent_store();
        let handle = handle();
        store
            .insert_connected(handle.clone(), vec!["code:edit".to_owned()], vec![])
            .await
            .expect("agent should insert");
        let server = TestServer::start_with_store(None, store).await;

        let malformed = authed_get(&server, "/v1/agents/not-a-handle/recv").await;
        assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
        assert_eq!(error_code(malformed).await, "malformed_agent_handle");

        let unknown = authed_get(&server, "/v1/agents/0123456789ABCDEFGHJKMNPQRT/recv").await;
        assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
        assert_eq!(error_code(unknown).await, "unknown_agent_handle");

        let timeout = authed_get(
            &server,
            &format!("/v1/agents/{}/recv?timeout_ms=1", handle.as_str()),
        )
        .await;
        assert_eq!(timeout.status(), StatusCode::REQUEST_TIMEOUT);
        assert_eq!(error_code(timeout).await, "recv_timeout");

        server.stop().await;
    }

    #[tokio::test]
    async fn close_removes_handle_and_unknown_afterward() {
        let store = agent_store();
        let handle = handle();
        store
            .insert_connected(handle.clone(), vec!["code:edit".to_owned()], vec![])
            .await
            .expect("agent should insert");
        let server = TestServer::start_with_store(None, store).await;

        let response = reqwest::Client::new()
            .delete(server.url(&format!("/v1/agents/{}", handle.as_str())))
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {}", server.record.token),
            )
            .send()
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        let body = response
            .json::<super::CloseResponse>()
            .await
            .expect("response should decode");
        assert!(body.ok);
        assert_eq!(body.agent_handle, handle.as_str());

        let unknown = authed_get(
            &server,
            &format!("/v1/agents/{}/recv?timeout_ms=1", handle.as_str()),
        )
        .await;
        assert_eq!(unknown.status(), StatusCode::NOT_FOUND);

        server.stop().await;
    }

    #[tokio::test]
    async fn agents_status_includes_agent_snapshots() {
        let store = agent_store();
        let handle = handle();
        store
            .insert_connected(
                handle.clone(),
                vec!["code:edit".to_owned()],
                vec!["elf".to_owned()],
            )
            .await
            .expect("agent should insert");
        let server = TestServer::start_with_store(None, store).await;

        let status = server
            .client()
            .agents()
            .await
            .expect("agents should succeed");

        assert_eq!(status.agents.len(), 1);
        assert_eq!(status.agents[0].agent_handle, handle.as_str());
        assert_eq!(status.agents[0].state, "connected");
        assert_eq!(status.agents[0].capabilities, ["code:edit"]);
        assert_eq!(status.agents[0].dialects, ["elf"]);

        server.stop().await;
    }

    struct TestServer {
        record: DiscoveryRecord,
        task: JoinHandle<Result<(), super::LocalApiError>>,
    }

    impl TestServer {
        async fn start(discovery_file: Option<PathBuf>) -> Self {
            Self::start_with_store(discovery_file, agent_store()).await
        }

        async fn start_with_store(discovery_file: Option<PathBuf>, store: AgentStore) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("listener should bind");
            let addr = listener.local_addr().expect("local addr should exist");
            let record = sample_record(addr);
            let task_record = record.clone();
            let task = tokio::spawn(async move {
                serve_local_api_with_agents(listener, task_record, discovery_file, store).await
            });

            let server = Self { record, task };
            server.wait_until_ready().await;
            server
        }

        fn client(&self) -> LocalApiClient {
            LocalApiClient::from_discovery(&self.record).expect("client should build")
        }

        fn url(&self, path: &str) -> String {
            format!("http://{}{}", self.record.addr, path)
        }

        async fn wait_until_ready(&self) {
            let client = self.client();
            for _ in 0..20 {
                if client.ping().await.is_ok() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            panic!("server did not become ready");
        }

        async fn stop(self) {
            let _ = self.client().stop().await;
            self.await_stopped().await;
        }

        async fn await_stopped(self) {
            self.task
                .await
                .expect("server task should not panic")
                .expect("server should stop cleanly");
        }
    }

    fn sample_record(addr: SocketAddr) -> DiscoveryRecord {
        DiscoveryRecord {
            pid: 12345,
            addr,
            token: "local-api-test-token".to_owned(),
            started_at: OffsetDateTime::from_unix_timestamp(1_800_000_000)
                .expect("timestamp should be valid"),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            api_version: LOCAL_API_VERSION,
        }
    }

    fn agent_store() -> AgentStore {
        AgentStore::new(AgentStoreConfig {
            agent_id_prefix: "local-agent".to_owned(),
            max_messages_per_handle: 10,
            max_bytes_per_handle: 1024,
        })
    }

    fn handle() -> AgentHandle {
        AgentHandle::new("0123456789ABCDEFGHJKMNPQRS").expect("handle should be valid")
    }

    async fn authed_get(server: &TestServer, path: &str) -> reqwest::Response {
        reqwest::Client::new()
            .get(server.url(path))
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {}", server.record.token),
            )
            .send()
            .await
            .expect("request should complete")
    }

    async fn error_code(response: reqwest::Response) -> String {
        response
            .json::<ErrorResponse>()
            .await
            .expect("error response should decode")
            .error
            .code
    }
}
