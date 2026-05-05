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
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use reqwest::header::{AUTHORIZATION, HeaderValue};
use serde::{Deserialize, Serialize};
use tokio::{net::TcpListener, sync::oneshot};

use crate::{
    constants::LOCAL_API_VERSION,
    daemon::{DiscoveryRecord, authenticated_headers},
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
    if !listener.local_addr()?.ip().is_loopback() {
        return Err(LocalApiError::Server(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "local API listener must be bound to loopback",
        )));
    }

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let state = AppState {
        record: Arc::new(record),
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
    Ok(Json(AgentsResponse {
        daemon: DaemonStatus {
            pid: state.record.pid,
            addr: state.record.addr,
            version: state.record.version.clone(),
            api_version: state.record.api_version,
        },
        agents: Vec::new(),
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
        serve_local_api,
    };
    use crate::{constants::LOCAL_API_VERSION, daemon::DiscoveryRecord};

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

    struct TestServer {
        record: DiscoveryRecord,
        task: JoinHandle<Result<(), super::LocalApiError>>,
    }

    impl TestServer {
        async fn start(discovery_file: Option<PathBuf>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("listener should bind");
            let addr = listener.local_addr().expect("local addr should exist");
            let record = sample_record(addr);
            let task_record = record.clone();
            let task = tokio::spawn(async move {
                serve_local_api(listener, task_record, discovery_file).await
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
}
