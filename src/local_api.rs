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

use crate::cbcl_validation::{CbclValidationError, MessageKind, validate_for_send_with_context};
use crate::{
    chat::{ChatError, create_chat_agent},
    config::{AppConfig, ConfigError, Transport, validate_chat_handle},
    constants::{COMMAND_NAME, LOCAL_API_VERSION, MAX_RECV_TIMEOUT_MS},
    daemon::{
        AgentError, AgentHandle, AgentStore, AgentStoreConfig, DiscoveryRecord,
        MetaReplyDelivery, MetaReplyExpectation, authenticated_headers,
    },
    identity::ChatIdentity,
    router::{RouterError, create_router_agent},
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
pub struct SendRequest {
    pub kind: SendMessageKind,
    pub message: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SendMessageKind {
    Reply,
    Error,
    Progress,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SendResponse {
    pub ok: bool,
    pub agent_handle: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct MetaSubscribeRequest {
    pub pattern: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct MetaAckResponse {
    pub ok: bool,
    pub agent_handle: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct MetaPublishRequest {
    /// Complete `(define <name> ...)` CBCL form. The daemon validates it
    /// through cbcl-rs's R1–R5 pipeline before sending the
    /// `(meta (teach @router <define>))` envelope to the router.
    pub define: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct MetaPublishResponse {
    pub ok: bool,
    pub agent_handle: String,
    pub digest: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct MetaQueryRequest {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct MetaQueryResponse {
    pub ok: bool,
    pub agent_handle: String,
    pub digest: String,
    pub name: String,
    pub define: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct MetaListResponse {
    pub ok: bool,
    pub agent_handle: String,
    pub names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct CreateAgentRequest {
    /// SPEC-009: capability ≡ dialect. The agent declares the dialects
    /// it can perform; the daemon validates and forwards to the router.
    pub dialects: Vec<String>,
    /// Best-effort fetch+install each advertised dialect from the router
    /// after hello so R5 shape/protocol checks fire on the first message.
    /// Defaults to `true`; tests with mock routers that don't speak meta
    /// can set it to `false` to skip. Soft-fails per dialect (miss,
    /// timeout, or transport error) without failing the agent creation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_install_advertised: Option<bool>,
    /// Chat transport only: the channel (`@name`) to join. Defaults to the
    /// configured `[chat].channel`. Ignored by the router.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    /// Chat transport only: the agent's wire handle (`@name`), required for a
    /// chat hub — each process is its own separately-keyed member. Ignored by
    /// the router (which derives its wire id from the local handle).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    /// Chat transport only: capability token or invite for a *private* channel
    /// (the hub's `:cap`). Omit for public channels. Ignored by the router.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cap: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct CreateAgentResponse {
    pub agent_handle: String,
    pub router_agent_id: String,
    pub dialects: Vec<String>,
    pub state: String,
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
    /// Performative of the offending message, if applicable. Surfaced
    /// for R5 violations (`shape_violation`, `causal_violation`) so
    /// callers can correlate the rejection with the dialect's blame
    /// rules without re-parsing the message body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub performative: Option<String>,
    /// Receipt thread of the offending message, if applicable.
    /// Surfaced for R5 violations so callers can correlate the
    /// rejection with the dispatched ask that originated the chain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread: Option<String>,
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

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum LocalApiRequestError {
    AuthFailure,
    Api(ErrorResponse, StatusCode),
    RequestFailed(String),
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
    config: Arc<AppConfig>,
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

    pub async fn create_agent(
        &self,
        request: &CreateAgentRequest,
    ) -> Result<CreateAgentResponse, LocalApiRequestError> {
        let response = self
            .http
            .post(self.url("/v1/agents"))
            .header(AUTHORIZATION, self.auth_header.clone())
            .json(request)
            .send()
            .await
            .map_err(|error| LocalApiRequestError::RequestFailed(error.to_string()))?;

        decode_api_response(response).await
    }

    pub async fn recv(
        &self,
        handle: &AgentHandle,
        timeout_ms: Option<u64>,
    ) -> Result<RecvResponse, LocalApiRequestError> {
        let mut request = self
            .http
            .get(self.url(&format!("/v1/agents/{}/recv", handle.as_str())))
            .header(AUTHORIZATION, self.auth_header.clone());
        if let Some(timeout_ms) = timeout_ms {
            request = request.query(&[("timeout_ms", timeout_ms)]);
        }

        let response = request
            .send()
            .await
            .map_err(|error| LocalApiRequestError::RequestFailed(error.to_string()))?;

        decode_api_response(response).await
    }

    pub async fn send(
        &self,
        handle: &AgentHandle,
        request: &SendRequest,
    ) -> Result<SendResponse, LocalApiRequestError> {
        let response = self
            .http
            .post(self.url(&format!("/v1/agents/{}/send", handle.as_str())))
            .header(AUTHORIZATION, self.auth_header.clone())
            .json(request)
            .send()
            .await
            .map_err(|error| LocalApiRequestError::RequestFailed(error.to_string()))?;

        decode_api_response(response).await
    }

    pub async fn meta_subscribe(
        &self,
        handle: &AgentHandle,
        request: &MetaSubscribeRequest,
    ) -> Result<MetaAckResponse, LocalApiRequestError> {
        let response = self
            .http
            .post(self.url(&format!(
                "/v1/agents/{}/meta/subscribe",
                handle.as_str()
            )))
            .header(AUTHORIZATION, self.auth_header.clone())
            .json(request)
            .send()
            .await
            .map_err(|error| LocalApiRequestError::RequestFailed(error.to_string()))?;
        decode_api_response(response).await
    }

    pub async fn meta_unsubscribe(
        &self,
        handle: &AgentHandle,
    ) -> Result<MetaAckResponse, LocalApiRequestError> {
        let response = self
            .http
            .post(self.url(&format!(
                "/v1/agents/{}/meta/unsubscribe",
                handle.as_str()
            )))
            .header(AUTHORIZATION, self.auth_header.clone())
            .send()
            .await
            .map_err(|error| LocalApiRequestError::RequestFailed(error.to_string()))?;
        decode_api_response(response).await
    }

    pub async fn meta_publish(
        &self,
        handle: &AgentHandle,
        request: &MetaPublishRequest,
    ) -> Result<MetaPublishResponse, LocalApiRequestError> {
        let response = self
            .http
            .post(self.url(&format!(
                "/v1/agents/{}/meta/publish",
                handle.as_str()
            )))
            .header(AUTHORIZATION, self.auth_header.clone())
            .json(request)
            .send()
            .await
            .map_err(|error| LocalApiRequestError::RequestFailed(error.to_string()))?;
        decode_api_response(response).await
    }

    pub async fn meta_query(
        &self,
        handle: &AgentHandle,
        request: &MetaQueryRequest,
    ) -> Result<MetaQueryResponse, LocalApiRequestError> {
        let response = self
            .http
            .post(self.url(&format!("/v1/agents/{}/meta/query", handle.as_str())))
            .header(AUTHORIZATION, self.auth_header.clone())
            .json(request)
            .send()
            .await
            .map_err(|error| LocalApiRequestError::RequestFailed(error.to_string()))?;
        decode_api_response(response).await
    }

    pub async fn meta_list(
        &self,
        handle: &AgentHandle,
    ) -> Result<MetaListResponse, LocalApiRequestError> {
        let response = self
            .http
            .post(self.url(&format!("/v1/agents/{}/meta/list", handle.as_str())))
            .header(AUTHORIZATION, self.auth_header.clone())
            .send()
            .await
            .map_err(|error| LocalApiRequestError::RequestFailed(error.to_string()))?;
        decode_api_response(response).await
    }

    pub async fn close(&self, handle: &AgentHandle) -> Result<CloseResponse, LocalApiRequestError> {
        let response = self
            .http
            .delete(self.url(&format!("/v1/agents/{}", handle.as_str())))
            .header(AUTHORIZATION, self.auth_header.clone())
            .send()
            .await
            .map_err(|error| LocalApiRequestError::RequestFailed(error.to_string()))?;

        decode_api_response(response).await
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

async fn decode_api_response<T: for<'de> Deserialize<'de>>(
    response: reqwest::Response,
) -> Result<T, LocalApiRequestError> {
    if response.status() == StatusCode::UNAUTHORIZED {
        return Err(LocalApiRequestError::AuthFailure);
    }

    let status = response.status();
    if !status.is_success() {
        let error = response
            .json::<ErrorResponse>()
            .await
            .map_err(|error| LocalApiRequestError::DecodeFailed(error.to_string()))?;
        return Err(LocalApiRequestError::Api(error, status));
    }

    response
        .json::<T>()
        .await
        .map_err(|error| LocalApiRequestError::DecodeFailed(error.to_string()))
}

impl fmt::Display for LocalApiRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthFailure => write!(formatter, "local daemon authentication failed"),
            Self::Api(error, status) => {
                write!(formatter, "{}: {}", status, error.error.message)
            }
            Self::RequestFailed(error) => write!(formatter, "request failed: {error}"),
            Self::DecodeFailed(error) => write!(formatter, "failed to decode response: {error}"),
        }
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
                "daemon_api_incompatible: CLI API version {cli_api_version}, daemon API version {daemon_api_version:?}, daemon version {daemon_version:?}",
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
        AppConfig::default(),
    )
    .await
}

pub async fn serve_local_api_with_agents(
    listener: TcpListener,
    record: DiscoveryRecord,
    discovery_file: Option<PathBuf>,
    agents: AgentStore,
    config: AppConfig,
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
        config: Arc::new(config),
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
        .route("/v1/agents", get(agents).post(create_agent))
        .route("/v1/agents/{handle}/recv", get(recv))
        .route("/v1/agents/{handle}/send", post(send))
        .route(
            "/v1/agents/{handle}/meta/subscribe",
            post(meta_subscribe),
        )
        .route(
            "/v1/agents/{handle}/meta/unsubscribe",
            post(meta_unsubscribe),
        )
        .route("/v1/agents/{handle}/meta/publish", post(meta_publish))
        .route("/v1/agents/{handle}/meta/query", post(meta_query))
        .route("/v1/agents/{handle}/meta/list", post(meta_list))
        .route("/v1/agents/{handle}", delete(close_agent))
        .route("/v1/stop", post(stop))
        .with_state(state)
}

async fn create_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateAgentRequest>,
) -> Result<Json<CreateAgentResponse>, ApiError> {
    authorize(&state, &headers)?;
    reject_if_stopping(&state)?;
    AgentStore::validate_advertisement(&request.dialects).map_err(agent_error_to_api)?;
    // The configured hub URL's path decides the transport (config::transport).
    match state.config.transport().map_err(config_error_to_api)? {
        Transport::Router => create_router_transport_agent(state, request).await,
        Transport::Chat => create_chat_transport_agent(state, request).await,
    }
}

/// Router transport: connect to cbcl-router, advertise dialects, and best-effort
/// install each advertised dialect via `@router` so R5 can enforce shape from
/// the first message.
async fn create_router_transport_agent(
    state: AppState,
    request: CreateAgentRequest,
) -> Result<Json<CreateAgentResponse>, ApiError> {
    let router = state
        .config
        .validate_router()
        .map_err(config_error_to_api)?;
    let dialects = request.dialects.clone();
    // Per-request override wins; otherwise fall back to the daemon-level
    // `[agent].auto_install_advertised` default (true in production, off
    // in tests that set `CBCL_AGENT_AUTO_INSTALL_ADVERTISED=false`).
    let auto_install = request
        .auto_install_advertised
        .unwrap_or(state.config.agent.auto_install_advertised);
    let created = create_router_agent(
        state.agents.clone(),
        &router,
        &state.config.agent.agent_id_prefix,
        request.dialects,
    )
    .await
    .map_err(router_error_to_api)?;

    if auto_install {
        auto_install_advertised_dialects(&state.agents, &created.agent_handle, &dialects).await;
    }

    Ok(Json(CreateAgentResponse {
        agent_handle: created.agent_handle.as_str().to_owned(),
        router_agent_id: created.router_agent_id,
        dialects: created.dialects,
        state: "connected".to_owned(),
    }))
}

/// Chat transport: join a cbcl-chat channel as a signed member. The wire handle
/// is per-process and required; its Ed25519 key lives at
/// `<identity_dir>/<handle>.key` (loaded or created). The router-specific
/// auto-install step is skipped — a chat hub has no `@router`.
async fn create_chat_transport_agent(
    state: AppState,
    request: CreateAgentRequest,
) -> Result<Json<CreateAgentResponse>, ApiError> {
    let chat = state.config.validate_chat().map_err(config_error_to_api)?;
    let wire_handle = request
        .handle
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "missing_chat_handle",
                "chat agents require a wire handle",
                Some(
                    "pass --handle @name, e.g. `hark init --handle @aria --channel @general --dialect cite`"
                        .to_owned(),
                ),
            )
        })?;
    validate_chat_handle("handle", wire_handle).map_err(config_error_to_api)?;
    let channel = match request
        .channel
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(channel) => {
            validate_chat_handle("channel", channel).map_err(config_error_to_api)?;
            channel.to_owned()
        }
        None => chat.channel.clone(),
    };
    let dialects = request.dialects.clone();
    let key_path = chat
        .identity_dir
        .join(format!("{}.key", chat_key_filename(wire_handle)));
    let identity = ChatIdentity::load_or_create(&key_path).map_err(|error| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "chat_identity_unavailable",
            format!(
                "could not load or create the chat identity at {}: {error}",
                key_path.display()
            ),
            None,
        )
    })?;
    let handle = create_chat_agent(
        state.agents.clone(),
        &chat.ws_url,
        &channel,
        wire_handle,
        request.dialects,
        request.cap.clone(),
        chat.claim_window,
        chat.liveness_timeout,
        std::sync::Arc::new(identity),
    )
    .await
    .map_err(chat_error_to_api)?;

    Ok(Json(CreateAgentResponse {
        agent_handle: handle.as_str().to_owned(),
        router_agent_id: wire_handle.to_owned(),
        dialects,
        state: "connected".to_owned(),
    }))
}

/// Map a wire handle to a key filename: strip the leading `@` and keep only
/// filename-safe characters. Falls back to `agent` if nothing remains.
fn chat_key_filename(handle: &str) -> String {
    let name: String = handle
        .trim_start_matches('@')
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if name.is_empty() {
        "agent".to_owned()
    } else {
        name
    }
}

/// Per-dialect best-effort meta-query so the publisher's local R5 pipeline
/// can enforce shape/protocol constraints on the very first outbound and
/// inbound simple message. Each query is sequential (the agent's
/// `pending_meta_reply` slot is single-occupancy) and uses a short timeout
/// so a non-responsive router does not stall agent creation.
///
/// All failure modes — `Reply` (router does not yet know the dialect),
/// `PushInstallFailed`, transport errors, timeouts — are logged at
/// info/warn level under target `hark::auto_install` and do **not** fail
/// the agent. The contract is "advertised dialects MAY be R5-enforced
/// immediately"; nothing breaks if they aren't.
async fn auto_install_advertised_dialects(
    store: &crate::daemon::AgentStore,
    handle: &crate::daemon::AgentHandle,
    dialects: &[String],
) {
    use crate::daemon::{MetaReplyDelivery, MetaReplyExpectation};

    for name in dialects {
        let frame = crate::router::build_meta_query_frame(name);
        let outcome = store
            .send_meta_and_await(
                handle,
                frame,
                MetaReplyExpectation::ReplyOrPushNamed(name.clone()),
                AUTO_INSTALL_QUERY_TIMEOUT,
            )
            .await;
        match outcome {
            Ok(MetaReplyDelivery::PushInstalled { name: installed, digest, .. }) => {
                tracing::info!(
                    target: "hark::auto_install",
                    handle = handle.as_str(),
                    name = %installed,
                    digest = %digest,
                    "installed advertised dialect from router on init",
                );
            }
            Ok(MetaReplyDelivery::Reply(_)) => {
                tracing::info!(
                    target: "hark::auto_install",
                    handle = handle.as_str(),
                    name = %name,
                    "router does not yet know advertised dialect; R5 will not enforce its constraints until it is published locally or arrives over subscribe",
                );
            }
            Ok(MetaReplyDelivery::PushInstallFailed { reason, .. }) => {
                tracing::warn!(
                    target: "hark::auto_install",
                    handle = handle.as_str(),
                    name = %name,
                    %reason,
                    "router teach-back for advertised dialect failed R5 locally; not installed",
                );
            }
            Err(error) => {
                tracing::warn!(
                    target: "hark::auto_install",
                    handle = handle.as_str(),
                    name = %name,
                    ?error,
                    "meta query for advertised dialect failed; skipping local install",
                );
            }
        }
    }
}

const AUTO_INSTALL_QUERY_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(1500);

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

async fn send(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(handle): Path<String>,
    Json(request): Json<SendRequest>,
) -> Result<Json<SendResponse>, ApiError> {
    authorize(&state, &headers)?;
    reject_if_stopping(&state)?;
    let handle = parse_handle(handle)?;
    let kind = MessageKind::from(request.kind);

    // R5 Phase B: drive `run_pipeline_full` for outbound simple-message
    // validation so shape (REQ-220) and causal (REQ-200) violations are
    // surfaced as the dedicated error codes / HTTP 422 / CLI exit 8. The
    // per-handle dialect cache supplies the registry; the per-handle
    // causal store supplies the predecessor index used by step 6a.
    let dialect_cache = state
        .agents
        .dialect_cache_handle(&handle)
        .await
        .map_err(agent_error_to_api)?;
    let store_arc = state
        .agents
        .store_handle(&handle)
        .await
        .map_err(agent_error_to_api)?;
    let registry = dialect_cache.registry_snapshot();

    // Serialise concurrent /send requests on this handle through a
    // per-handle send sequencer. Within the critical section we run
    // (validate, append, enqueue) so the wire order on the router
    // WebSocket matches the store-append order: a frame whose
    // :caused-by references another frame from this handle is
    // guaranteed to be enqueued strictly after its predecessor.
    //
    // Critically, the *store* mutex is released BEFORE we await the
    // writer task's oneshot ack inside `send_outbound`. Holding both
    // across that await would deadlock: the router receive loop runs
    // outbound writes AND inbound `verify_inbound_against_registry`
    // in the same `tokio::select!` task; the inbound branch needs the
    // store mutex, the outbound branch is what posts the ack we're
    // waiting on. The sequencer mutex, by contrast, is only taken by
    // this handler — never by the receive loop — so holding it across
    // the ack is safe.
    let sequencer = state
        .agents
        .send_sequencer(&handle)
        .await
        .map_err(agent_error_to_api)?;
    let _send_seq = sequencer.lock().await;

    {
        let mut guard = store_arc.lock().await;
        let validated =
            validate_for_send_with_context(&request.message, kind, &registry, &mut guard)
                .map_err(cbcl_validation_error_to_api)?;
        if let Some((hash, thread, message)) = build_outbound_store_entry(&validated) {
            use cbcl_core::store::MessageStore as _;
            let _ = guard.append(hash, thread, message);
        }
        // `guard` drops here, releasing the store mutex before the
        // ack-await below.
    }

    state
        .agents
        .send_outbound(&handle, request.message)
        .await
        .map_err(agent_error_to_api)?;
    drop(_send_seq);

    Ok(Json(SendResponse {
        ok: true,
        agent_handle: handle.as_str().to_owned(),
    }))
}

/// Compute the `(hash, thread, message)` triple to append for an outbound
/// simple message. Mirrors the inbound helper in `router.rs` (Phase C) so
/// both directions share the same content-hash recipe — sha256 over the
/// canonical encoding of the innermost simple message's s-expression.
fn build_outbound_store_entry(
    validated: &crate::cbcl_validation::ValidatedMessage,
) -> Option<(
    cbcl_core::store::ContentHash,
    cbcl_core::store::ThreadId,
    cbcl_core::message::Message,
)> {
    use cbcl_core::canonical::canonical_encode;
    use cbcl_core::sexpr::SExpr;
    use cbcl_core::store::{ContentHash, ThreadId};
    use sha2::{Digest, Sha256};

    let simple = validated.message.innermost_simple()?;
    let cbcl_core::message::Message::Simple { thread, .. } = simple else {
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

async fn meta_subscribe(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(handle): Path<String>,
    Json(request): Json<MetaSubscribeRequest>,
) -> Result<Json<MetaAckResponse>, ApiError> {
    authorize(&state, &headers)?;
    reject_if_stopping(&state)?;
    reject_if_chat_transport(&state)?;
    let handle = parse_handle(handle)?;
    let pattern = validate_subscribe_pattern(&request.pattern)?;
    let frame = crate::router::build_meta_subscribe_frame(pattern);
    state
        .agents
        .send_outbound(&handle, frame)
        .await
        .map_err(agent_error_to_api)?;
    Ok(Json(MetaAckResponse {
        ok: true,
        agent_handle: handle.as_str().to_owned(),
    }))
}

async fn meta_unsubscribe(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(handle): Path<String>,
) -> Result<Json<MetaAckResponse>, ApiError> {
    authorize(&state, &headers)?;
    reject_if_stopping(&state)?;
    reject_if_chat_transport(&state)?;
    let handle = parse_handle(handle)?;
    let frame = crate::router::build_meta_unsubscribe_frame();
    state
        .agents
        .send_outbound(&handle, frame)
        .await
        .map_err(agent_error_to_api)?;
    Ok(Json(MetaAckResponse {
        ok: true,
        agent_handle: handle.as_str().to_owned(),
    }))
}

async fn meta_publish(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(handle): Path<String>,
    Json(request): Json<MetaPublishRequest>,
) -> Result<Json<MetaPublishResponse>, ApiError> {
    authorize(&state, &headers)?;
    reject_if_stopping(&state)?;
    reject_if_chat_transport(&state)?;
    let handle = parse_handle(handle)?;
    let define = request.define.trim();
    validate_define_for_publish(define)?;
    let frame = crate::router::build_meta_teach_frame(define);
    let delivery = state
        .agents
        .send_meta_and_await(&handle, frame, MetaReplyExpectation::Reply, META_REPLY_TIMEOUT)
        .await
        .map_err(agent_error_to_api)?;
    let reply = match delivery {
        MetaReplyDelivery::Reply(frame) => frame,
        // Expectation::Reply filters out pushes — this is the daemon
        // protocol invariant being broken, not a user error.
        other => {
            return Err(ApiError::new(
                StatusCode::BAD_GATEWAY,
                "meta_reply_malformed",
                "router responded with a dialect push to a publish request",
                Some(other.frame_owned()),
            ));
        }
    };
    let parsed = parse_meta_reply_params(&reply).map_err(|reason| ApiError::new(
        StatusCode::BAD_GATEWAY,
        "meta_reply_malformed",
        format!("router reply could not be parsed: {reason}"),
        Some(reply.clone()),
    ))?;
    let digest = parsed
        .get("digest")
        .cloned()
        .ok_or_else(|| ApiError::new(
            StatusCode::BAD_GATEWAY,
            "meta_reply_missing_digest",
            "router reply did not include a digest",
            Some(reply.clone()),
        ))?;
    let name = parsed
        .get("name")
        .cloned()
        .ok_or_else(|| ApiError::new(
            StatusCode::BAD_GATEWAY,
            "meta_reply_missing_name",
            "router reply did not include a name",
            Some(reply.clone()),
        ))?;

    // Install into the publishing handle's local dialect cache so the
    // outbound R5 pipeline (Phase B) can see the freshly-published
    // shape/protocol on the very next `send`. Without this, agents that
    // publish a dialect skip their own R5 constraints until they also
    // `dialect query` the same name back. A local install failure here is
    // not fatal: the router already accepted the teach, so we still report
    // the publish as successful and surface a warn-level event.
    let local_cache = state
        .agents
        .dialect_cache_handle(&handle)
        .await
        .map_err(agent_error_to_api)?;
    if let Err(error) = local_cache.try_install(&name, define) {
        tracing::warn!(
            target: "hark::dialect_cache",
            handle = handle.as_str(),
            name = %name,
            ?error,
            "publish: local dialect-cache install failed after router ack",
        );
    }

    Ok(Json(MetaPublishResponse {
        ok: true,
        agent_handle: handle.as_str().to_owned(),
        digest,
        name,
    }))
}

async fn meta_query(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(handle): Path<String>,
    Json(request): Json<MetaQueryRequest>,
) -> Result<Json<MetaQueryResponse>, ApiError> {
    authorize(&state, &headers)?;
    reject_if_stopping(&state)?;
    reject_if_chat_transport(&state)?;
    let handle = parse_handle(handle)?;
    validate_dialect_name(&request.name)?;
    let frame = crate::router::build_meta_query_frame(&request.name);
    let delivery = state
        .agents
        .send_meta_and_await(
            &handle,
            frame,
            MetaReplyExpectation::ReplyOrPushNamed(request.name.clone()),
            META_REPLY_TIMEOUT,
        )
        .await
        .map_err(agent_error_to_api)?;
    // Three shapes possible:
    //   * `PushInstalled` — `(meta (teach @<self> (define <name> ...)))`
    //     that passed R1–R5 and is now in the daemon cache. Report success.
    //   * `PushInstallFailed` — same shape but the define was rejected.
    //     Surface as a gateway-level validation failure rather than
    //     returning a digest for a body that wasn't actually installed.
    //   * `Reply` — miss reply, typically with `:reason "..."`.
    match delivery {
        MetaReplyDelivery::PushInstalled {
            name,
            define_form,
            digest,
            ..
        } => Ok(Json(MetaQueryResponse {
            ok: true,
            agent_handle: handle.as_str().to_owned(),
            digest,
            name,
            define: define_form,
        })),
        MetaReplyDelivery::PushInstallFailed { reason, frame, .. } => Err(ApiError::new(
            StatusCode::BAD_GATEWAY,
            "teach_back_rejected",
            format!("router teach-back failed R1–R5: {reason}"),
            Some(frame),
        )),
        MetaReplyDelivery::Reply(reply) => {
            let parsed = parse_meta_reply_params(&reply).unwrap_or_default();
            let reason = parsed
                .get("reason")
                .cloned()
                .unwrap_or_else(|| "router-does-not-speak".to_owned());
            Err(ApiError::new(
                StatusCode::NOT_FOUND,
                "dialect_unknown_to_router",
                reason,
                Some(reply),
            ))
        }
    }
}

async fn meta_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(handle): Path<String>,
) -> Result<Json<MetaListResponse>, ApiError> {
    authorize(&state, &headers)?;
    reject_if_stopping(&state)?;
    reject_if_chat_transport(&state)?;
    let handle = parse_handle(handle)?;
    let frame = crate::router::build_meta_query_list_frame();
    let delivery = state
        .agents
        .send_meta_and_await(&handle, frame, MetaReplyExpectation::Reply, META_REPLY_TIMEOUT)
        .await
        .map_err(agent_error_to_api)?;
    let reply = match delivery {
        MetaReplyDelivery::Reply(frame) => frame,
        other => {
            return Err(ApiError::new(
                StatusCode::BAD_GATEWAY,
                "meta_reply_malformed",
                "router responded with a dialect push to a list request",
                Some(other.frame_owned()),
            ));
        }
    };
    let parsed = parse_meta_reply_params(&reply).map_err(|reason| ApiError::new(
        StatusCode::BAD_GATEWAY,
        "meta_reply_malformed",
        format!("router list reply could not be parsed: {reason}"),
        Some(reply.clone()),
    ))?;
    let names = parsed
        .get("names")
        .map(|joined| {
            joined
                .split_whitespace()
                .map(|s| s.to_owned())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Ok(Json(MetaListResponse {
        ok: true,
        agent_handle: handle.as_str().to_owned(),
        names,
    }))
}

fn validate_dialect_name(name: &str) -> Result<(), ApiError> {
    if name.is_empty()
        || name
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '(' | ')' | '"' | '\\'))
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_dialect",
            "dialect name must be a non-empty CBCL symbol",
            None,
        ));
    }
    Ok(())
}

const META_REPLY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Run cbcl-rs's R1–R5 pipeline on `(meta <define>)` so we don't ship a
/// malformed define to the router. Mirrors the dialect-cache's
/// `try_install` guard on the receive path.
fn validate_define_for_publish(define: &str) -> Result<(), ApiError> {
    if define.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "cbcl_validation_failed",
            "define body is empty",
            None,
        ));
    }
    // Require the body's outermost form to be `(define ...)`. `run_pipeline`
    // also accepts other meta operations (e.g. `(query ...)`) when wrapped,
    // and those would otherwise smuggle past the publish surface as a teach.
    match cbcl_parser::parse(define) {
        Ok(cbcl_core::sexpr::SExpr::List(items))
            if matches!(
                items.first(),
                Some(cbcl_core::sexpr::SExpr::Atom(cbcl_core::sexpr::Atom::Symbol(s)))
                    if s.as_str() == "define"
            ) => {}
        Ok(_) => {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "cbcl_validation_failed",
                "publish body must be a `(define ...)` form",
                None,
            ));
        }
        Err(error) => {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "cbcl_validation_failed",
                format!("define failed to parse: {error}"),
                None,
            ));
        }
    }
    let envelope = format!("(meta {define})");
    match cbcl_parser::run_pipeline(&envelope) {
        cbcl_parser::PipelineResult::Success(_) => Ok(()),
        cbcl_parser::PipelineResult::ParseError(error) => Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "cbcl_validation_failed",
            format!("define failed to parse: {error}"),
            None,
        )),
        cbcl_parser::PipelineResult::ValidationError(error) => Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "cbcl_validation_failed",
            format!("define failed R1–R5: {error}"),
            None,
        )),
        cbcl_parser::PipelineResult::Pending { .. }
        | cbcl_parser::PipelineResult::Buffered { .. } => Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "cbcl_validation_failed",
            "define pipeline returned unexpected pending/buffered state",
            None,
        )),
    }
}

/// Extract `:<key> "<value>"` and `:<key> <symbol>` pairs from a reply
/// frame like
/// `(reply @asker "ok" :thread "rcp-..." :digest "abc..." :name foo)`.
/// Stops at the first close-paren outside a string and ignores positional
/// args (the recipient, the status content). Strings are unescaped for
/// `\\` and `\"`. Best-effort: returns `Err(_)` if the frame doesn't
/// look like a single top-level list at all.
fn parse_meta_reply_params(text: &str) -> Result<std::collections::HashMap<String, String>, String> {
    let bytes = text.as_bytes();
    let mut params = std::collections::HashMap::new();
    let mut i = 0;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= bytes.len() || bytes[i] != b'(' {
        return Err("reply does not start with `(`".to_owned());
    }
    while i < bytes.len() {
        if bytes[i] == b':' {
            let start = i + 1;
            let mut j = start;
            while j < bytes.len() && !bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            let key = std::str::from_utf8(&bytes[start..j])
                .map_err(|_| "non-utf8 keyword".to_owned())?
                .to_owned();
            // skip whitespace to the value
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            if j >= bytes.len() {
                return Err(format!(":{key} had no value"));
            }
            if bytes[j] == b'"' {
                // quoted string with `\\` and `\"` escapes
                j += 1;
                let mut buf = String::new();
                while j < bytes.len() {
                    match bytes[j] {
                        b'\\' if j + 1 < bytes.len() => {
                            buf.push(bytes[j + 1] as char);
                            j += 2;
                        }
                        b'"' => {
                            j += 1;
                            break;
                        }
                        c => {
                            buf.push(c as char);
                            j += 1;
                        }
                    }
                }
                params.insert(key, buf);
            } else {
                let start = j;
                while j < bytes.len() && !bytes[j].is_ascii_whitespace() && bytes[j] != b')' {
                    j += 1;
                }
                let value = std::str::from_utf8(&bytes[start..j])
                    .map_err(|_| "non-utf8 value".to_owned())?
                    .to_owned();
                params.insert(key, value);
            }
            i = j;
        } else {
            i += 1;
        }
    }
    Ok(params)
}

/// Reject patterns containing characters that would break the canonical
/// `(subscribe (speak? <pattern>))` envelope. Slice 2 router supports the
/// pattern grammar `*`, `<prefix>*`, and `<exact>` — all of which are
/// composed of CBCL symbol characters. Anything with whitespace, parens,
/// or quotes here would either fail upstream parsing or smuggle extra
/// list elements past the builder; reject it locally with a clear code.
fn validate_subscribe_pattern(pattern: &str) -> Result<&str, ApiError> {
    let invalid = || {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_subscribe_pattern",
            "subscribe pattern must be a non-empty CBCL symbol; wildcard \
             grammar is `*`, `<prefix>*`, or an exact name",
            None,
        )
    };
    if pattern.is_empty()
        || pattern
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '(' | ')' | '"' | '\\'))
    {
        return Err(invalid());
    }
    // Wildcard grammar: at most one `*`, only as the whole pattern or as a
    // trailing suffix. Patterns like `foo*bar`, `**`, or `*foo` violate the
    // router's documented matcher and should fail-fast before fire-and-forget
    // subscribe silently routes them across the wire.
    let stars = pattern.matches('*').count();
    if stars > 1 {
        return Err(invalid());
    }
    if stars == 1 && pattern != "*" && !pattern.ends_with('*') {
        return Err(invalid());
    }
    Ok(pattern)
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
            Some("run `hark daemon status` to list active handles".to_owned()),
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
        AgentError::MissingDialect => ApiError::new(
            StatusCode::BAD_REQUEST,
            "missing_dialect",
            "agent creation requires at least one dialect",
            None,
        ),
        AgentError::DuplicateDialect => ApiError::new(
            StatusCode::BAD_REQUEST,
            "duplicate_dialect",
            "agent creation request repeats a dialect",
            None,
        ),
        AgentError::InvalidDialect(message) => {
            ApiError::new(StatusCode::BAD_REQUEST, "invalid_dialect", message, None)
        }
        AgentError::MetaSendBusy => ApiError::new(
            StatusCode::CONFLICT,
            "meta_send_busy",
            "another meta send is already awaiting a router reply",
            None,
        ),
        AgentError::MetaReplyTimeout => ApiError::new(
            StatusCode::REQUEST_TIMEOUT,
            "meta_reply_timeout",
            "router did not reply to the meta send in time",
            None,
        ),
    }
}

fn config_error_to_api(error: ConfigError) -> ApiError {
    match error {
        ConfigError::MissingRouterWsUrl => ApiError::new(
            StatusCode::BAD_REQUEST,
            "missing_router_ws_url",
            "router WebSocket URL is not configured",
            Some(format!(
                "run `{COMMAND_NAME} config init` or set CBCL_ROUTER_WS"
            )),
        ),
        ConfigError::InvalidRouterWsUrl(message) => ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_router_ws_url",
            message,
            Some(format!(
                "run `{COMMAND_NAME} config path` to find config.toml"
            )),
        ),
        ConfigError::MissingRouterAuthToken => ApiError::new(
            StatusCode::BAD_REQUEST,
            "missing_router_auth_token",
            "router authentication token is not configured",
            Some(format!(
                "run `{COMMAND_NAME} config init` or set CBCL_ROUTER_AUTH_TOKEN"
            )),
        ),
        error => ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_router_ws_url",
            error.to_string(),
            None,
        ),
    }
}

fn router_error_to_api(error: RouterError) -> ApiError {
    match error {
        RouterError::AuthRejected => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "router_auth_rejected",
            "router rejected WebSocket authentication",
            None,
        ),
        RouterError::ConnectionFailed(message) => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "router_connection_failed",
            message,
            None,
        ),
        RouterError::HelloSendFailed(message) => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "router_connection_failed",
            message,
            None,
        ),
    }
}

fn chat_error_to_api(error: ChatError) -> ApiError {
    match error {
        ChatError::JoinRejected(slug) => ApiError::new(
            StatusCode::FORBIDDEN,
            "chat_join_rejected",
            format!("hub rejected the join: {slug}"),
            Some("for a private channel pass --cap <token-or-invite>".to_owned()),
        ),
        ChatError::JoinTimeout(_) => ApiError::new(
            StatusCode::GATEWAY_TIMEOUT,
            "chat_join_timeout",
            error.to_string(),
            None,
        ),
        ChatError::ConnectionFailed(message)
        | ChatError::Hello(message)
        | ChatError::HelloSendFailed(message) => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "chat_connection_failed",
            message,
            None,
        ),
        ChatError::Store(message) => {
            ApiError::new(StatusCode::BAD_REQUEST, "invalid_dialect", message, None)
        }
    }
}

/// Reject router-only dialect operations on a chat hub: there is no `@router` to
/// teach/query, and per-channel dialects (SPEC-005) are not yet implemented.
fn reject_if_chat_transport(state: &AppState) -> Result<(), ApiError> {
    if matches!(state.config.transport(), Ok(Transport::Chat)) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "not_supported_on_chat_hub",
            "dialect/router operations are not available on a chat hub (there is no @router); \
             per-channel dialects (SPEC-005) are not yet implemented",
            None,
        ));
    }
    Ok(())
}

fn cbcl_validation_error_to_api(error: CbclValidationError) -> ApiError {
    match error {
        CbclValidationError::KindMismatch { .. } => ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "message_kind_mismatch",
            error.to_string(),
            None,
        ),
        CbclValidationError::MissingThread => ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "missing_thread",
            error.to_string(),
            None,
        ),
        CbclValidationError::DuplicateThread => ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "duplicate_thread",
            error.to_string(),
            None,
        ),
        CbclValidationError::EmptyThread | CbclValidationError::NonStringThread => ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_thread",
            error.to_string(),
            None,
        ),
        CbclValidationError::ShapeViolation {
            ref detail,
            ref performative,
            ref thread,
        } => ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "shape_violation",
            detail.clone(),
            None,
        )
        .with_blame(performative.clone(), thread.clone()),
        CbclValidationError::CausalViolation {
            ref detail,
            ref performative,
            ref thread,
        } => ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "causal_violation",
            detail.clone(),
            None,
        )
        .with_blame(performative.clone(), thread.clone()),
        _ => ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "cbcl_validation_failed",
            error.to_string(),
            None,
        ),
    }
}

impl From<SendMessageKind> for MessageKind {
    fn from(kind: SendMessageKind) -> Self {
        match kind {
            SendMessageKind::Reply => Self::Reply,
            SendMessageKind::Error => Self::Error,
            SendMessageKind::Progress => Self::Progress,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
    hint: Option<String>,
    performative: Option<String>,
    thread: Option<String>,
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
            performative: None,
            thread: None,
        }
    }

    /// Attach R5 blame context (performative + thread) so the JSON
    /// error body surfaces what the spec advertises for
    /// `shape_violation` and `causal_violation`. Either side may be
    /// `None` when the pipeline couldn't extract it.
    fn with_blame(
        mut self,
        performative: Option<String>,
        thread: Option<String>,
    ) -> Self {
        self.performative = performative;
        self.thread = thread;
        self
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
                    performative: self.performative,
                    thread: self.thread,
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
        chat_key_filename, serve_local_api_with_agents,
    };

    #[test]
    fn chat_key_filename_sanitizes_handle() {
        assert_eq!(chat_key_filename("@aria"), "aria");
        assert_eq!(chat_key_filename("@team-bot_1"), "team-bot_1");
        // Path separators and other unsafe chars become underscores.
        assert_eq!(chat_key_filename("@a/b.c"), "a_b_c");
        // A handle that reduces to nothing falls back to a safe default.
        assert_eq!(chat_key_filename("@"), "agent");
    }
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
            .insert_connected(handle.clone(), vec!["elf".to_owned()])
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
            .insert_connected(handle.clone(), vec!["elf".to_owned()])
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
            .insert_connected(handle.clone(), vec!["elf".to_owned()])
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
            .insert_connected(handle.clone(), vec!["elf".to_owned()])
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
                serve_local_api_with_agents(
                    listener,
                    task_record,
                    discovery_file,
                    store,
                    crate::config::AppConfig::default(),
                )
                .await
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

    #[test]
    fn publish_rejects_non_define_body() {
        // `(query (speak? arena-v1))` is a valid meta op so `run_pipeline`
        // accepts it under `(meta ...)`, but it must not pass the publish
        // surface — that would silently teach a non-define payload to the
        // router.
        let error = super::validate_define_for_publish("(query (speak? arena-v1))")
            .expect_err("non-define publish body should be rejected");
        assert_eq!(error.code, "cbcl_validation_failed");
    }

    #[test]
    fn publish_rejects_unparseable_body() {
        let error = super::validate_define_for_publish("(define oops")
            .expect_err("syntax error should be rejected");
        assert_eq!(error.code, "cbcl_validation_failed");
    }

    #[test]
    fn subscribe_rejects_internal_wildcards() {
        // `foo*bar` and `**` have no banned characters but violate the
        // documented `(* | prefix* | exact)` grammar. The router would
        // treat them as exact, leaving the user with a silently invalid
        // subscription; reject locally.
        assert_eq!(
            super::validate_subscribe_pattern("foo*bar")
                .expect_err("internal wildcard should be rejected")
                .code,
            "invalid_subscribe_pattern"
        );
        assert_eq!(
            super::validate_subscribe_pattern("**")
                .expect_err("double wildcard should be rejected")
                .code,
            "invalid_subscribe_pattern"
        );
        assert_eq!(
            super::validate_subscribe_pattern("*foo")
                .expect_err("leading wildcard should be rejected")
                .code,
            "invalid_subscribe_pattern"
        );
    }

    #[test]
    fn subscribe_accepts_documented_grammar() {
        assert!(super::validate_subscribe_pattern("*").is_ok());
        assert!(super::validate_subscribe_pattern("arena-*").is_ok());
        assert!(super::validate_subscribe_pattern("arena-v1").is_ok());
    }
}
