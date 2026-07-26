use std::{
    collections::{HashMap, VecDeque},
    fs::{self, File, OpenOptions},
    io::{self, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use directories::BaseDirs;
use fs2::FileExt;
use rand::TryRngCore;
use rand::rngs::OsRng;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio::sync::{Mutex, Notify, mpsc, oneshot};

use cbcl_core::{
    message::Message,
    store::{ContentHash, MessageStore, ThreadId, ThreadedMessageStore},
};

use crate::{
    config::validate_dialect_id, constants::LOCAL_API_VERSION, dialect_cache::DialectCache,
    local_api::PingResponse,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AgentState {
    Connected,
    /// SPEC-026 CON-003: the hub socket ended at the transport level and the
    /// transport loop is re-establishing it on the [`crate::reconnect`]
    /// schedule. **Healthy for admission** — a `recv` keeps waiting and a send
    /// still reaches the transport loop, which refuses it as *retryable*. This
    /// is the state that makes a hub redeploy a blip rather than a bereavement
    /// (issue #25); marking such a handle [`AgentState::Unhealthy`] is terminal
    /// and is precisely the defect SPEC-026 exists to fix.
    Reconnecting,
    Unhealthy,
}

impl AgentState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::Reconnecting => "reconnecting",
            Self::Unhealthy => "unhealthy",
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct AgentHandle(String);

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AgentStatusSnapshot {
    pub agent_handle: String,
    pub router_agent_id: String,
    pub dialects: Vec<String>,
    pub state: AgentState,
    pub queued_messages: usize,
    pub queued_bytes: usize,
    pub unhealthy_reason: Option<String>,
    pub unhealthy_detail: Option<String>,
    /// The chat channel this agent joined (`@name`); `None` on the router
    /// transport, which has no channel notion.
    pub channel: Option<String>,
    /// SPEC-026 OBS-002: consecutive failed reconnect attempts. Zero whenever
    /// the state is not [`AgentState::Reconnecting`]. Kept separate from
    /// `unhealthy_reason`/`unhealthy_detail`, which retain their terminal-only
    /// meaning: an operator must be able to tell "coming back" from "dead".
    pub reconnect_attempts: u32,
    /// SPEC-026 OBS-002: the transport error that ended the socket, for the
    /// operator. `None` unless reconnecting.
    pub reconnect_detail: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AgentStoreConfig {
    pub agent_id_prefix: String,
    pub max_messages_per_handle: usize,
    pub max_bytes_per_handle: usize,
}

#[derive(Debug, Clone)]
pub struct AgentStore {
    inner: Arc<Mutex<AgentRegistry>>,
}

#[derive(Debug, Clone)]
pub struct AgentSendChannel {
    tx: mpsc::Sender<OutboundFrame>,
}

#[derive(Debug)]
pub struct OutboundFrame {
    pub message: String,
    pub result_tx: oneshot::Sender<Result<(), OutboundReject>>,
}

/// Why a transport loop refused to send an outbound frame. The `retryable`
/// bit is the load-bearing distinction: a *fatal* reject (WebSocket write
/// failed, connection closed, malformed frame) means the handle is dead and
/// must be marked unhealthy; a *retryable* reject (the MLS Welcome that makes
/// us a group member has not arrived yet — SPEC-013 REQ-023 fail-closed) is a
/// transient precondition that the very next attempt may satisfy, so it must
/// NOT poison the handle.
#[derive(Debug, Clone)]
pub struct OutboundReject {
    pub detail: String,
    pub retryable: bool,
}

impl OutboundReject {
    /// The handle is dead — mark it unhealthy.
    pub fn fatal(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
            retryable: false,
        }
    }

    /// A transient precondition failed — the same send may succeed shortly.
    pub fn retryable(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
            retryable: true,
        }
    }
}

#[derive(Debug, thiserror::Error, Clone, Eq, PartialEq)]
pub enum AgentError {
    #[error("malformed agent handle")]
    MalformedHandle,
    #[error("unknown agent handle")]
    UnknownHandle,
    #[error("agent handle is unhealthy")]
    Unhealthy {
        reason: String,
        detail: Option<String>,
    },
    /// A transient precondition blocked the send but the handle is still
    /// healthy — retry shortly. Today this is exclusively the MLS
    /// membership-not-yet-established case (no Welcome yet, SPEC-013 REQ-023):
    /// unlike [`AgentError::Unhealthy`], the handle is left usable.
    #[error("agent handle is not ready yet")]
    NotReady { detail: Option<String> },
    #[error("a receive call is already waiting for this handle")]
    RecvAlreadyWaiting,
    #[error("receive timed out")]
    RecvTimeout,
    #[error("queue overflow")]
    QueueOverflow,
    #[error("missing dialect")]
    MissingDialect,
    #[error("duplicate dialect")]
    DuplicateDialect,
    #[error("invalid dialect: {0}")]
    InvalidDialect(String),
    #[error("a meta send is already awaiting a router reply for this handle")]
    MetaSendBusy,
    #[error("meta send timed out waiting for router reply")]
    MetaReplyTimeout,
}

#[derive(Debug)]
struct AgentRegistry {
    config: AgentStoreConfig,
    agents: HashMap<AgentHandle, AgentEntry>,
    /// The session's active handle (REQ-003, SPEC-016 ADR-002): the most
    /// recently created agent. CLI commands fall back to it when
    /// `CBCL_AGENT_HANDLE` is unset, dropping the `eval` ritual.
    active: Option<AgentHandle>,
}

#[derive(Debug)]
struct AgentEntry {
    router_agent_id: String,
    dialects: Vec<String>,
    /// The chat channel this agent joined; `None` on the router transport.
    channel: Option<String>,
    state: AgentState,
    unhealthy_reason: Option<String>,
    unhealthy_detail: Option<String>,
    /// SPEC-026 OBS-002: reconnect progress, meaningful only while the state is
    /// [`AgentState::Reconnecting`].
    reconnect_attempts: u32,
    reconnect_detail: Option<String>,
    queue: VecDeque<QueuedMessage>,
    queued_bytes: usize,
    recv_waiter: Option<RecvWaiterId>,
    next_recv_waiter_id: u64,
    notify: Arc<Notify>,
    close_tx: Option<oneshot::Sender<()>>,
    send_channel: Option<AgentSendChannel>,
    /// Single-slot waiter for routing the next router meta-reply (a
    /// `(reply ...)` or `(meta (teach @<self> ...))` frame) back to a
    /// caller blocked in `send_meta_and_await`. `None` when no caller is
    /// waiting; the inbound classifier then falls through to the normal
    /// recv queue. One slot per agent — meta sends are serialised; a
    /// second concurrent call returns `MetaSendBusy`. The expectation
    /// filters which inbound frames satisfy the waiter, so an unsolicited
    /// dialect push from an active subscription cannot be misrouted as a
    /// reply to an in-flight publish/list/query.
    pending_meta_reply: Option<PendingMetaReply>,
    /// Per-handle append-only causal message store (R5 Phase A plumbing).
    ///
    /// Each agent connection has its own causal world: messages it has
    /// sent or received form an independent DAG keyed by `:thread`. The
    /// outbound (Phase B) and inbound (Phase C) pipelines will lock this
    /// store to feed `run_pipeline_full(&PipelineContext { store, .. })`.
    ///
    /// Held behind a `tokio::sync::Mutex` so the caller can drop the
    /// outer `AgentRegistry` lock (which also guards the queue) before
    /// the synchronous pipeline call. Wrapped in `Arc` to be cloned out
    /// to async tasks without holding `AgentRegistry`.
    pub store: Arc<Mutex<ThreadedMessageStore>>,
    /// Per-handle send sequencer (R5 Phase B fix). Serialises the
    /// (validate, append, enqueue) sequence across concurrent `/send`
    /// requests on this handle so the wire order on the router
    /// WebSocket matches the store-append order. **Must not be held by
    /// the router receive loop** — only the local-API outbound handler
    /// acquires this. The store mutex (`store`) is released before any
    /// `await` on the writer's oneshot ack, so a blocked inbound
    /// verification cannot deadlock the outbound writer.
    pub send_sequencer: Arc<Mutex<()>>,
    /// Per-agent dialect cache (R5 Phase B). SPEC-009 comment in
    /// `router.rs` notes the cache is per-agent ("installations made by
    /// this session don't leak across sessions"); to make the cache
    /// reachable from BOTH the router receive loop AND the outbound
    /// send handler in `local_api.rs` it lives on the registry entry.
    /// The router-create path replaces the default with its own cache.
    /// Cheap to clone — `DialectCache` is `Arc<RwLock<_>>` internally.
    pub dialect_cache: DialectCache,
}

#[derive(Debug)]
struct PendingMetaReply {
    expectation: MetaReplyExpectation,
    sender: oneshot::Sender<MetaReplyDelivery>,
}

/// What kind of router frame a `send_meta_and_await` caller is willing to
/// accept as the reply to their in-flight meta send. Used by
/// [`AgentStore::try_route_meta_reply`] to ignore unrelated frames (e.g. an
/// unsolicited dialect push arriving on an active subscription) so they
/// don't steal another command's slot.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum MetaReplyExpectation {
    /// Only a bare `(reply ...)` frame satisfies the waiter. Used by
    /// `publish` (meta teach reply) and `list` (meta query list reply).
    Reply,
    /// Either a bare `(reply ...)` (the miss case, e.g.
    /// `:reason "router-does-not-speak"`) OR a dialect-push teach-back
    /// whose inner `(define <name> ...)` matches the named dialect. Used
    /// by `query` (meta query speak?). Pushes for any other name fall
    /// through to the normal inbound queue.
    ReplyOrPushNamed(String),
}

/// What the router-receive loop hands to [`AgentStore::try_route_meta_reply`]
/// when an inbound frame may satisfy a pending meta waiter. Carries enough
/// information to (a) decide whether the expectation matches, and (b)
/// surface the install outcome to the awaiting caller so a teach-back that
/// failed R1–R5 is reported as an error instead of a successful query.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum MetaReplyDelivery {
    /// A bare `(reply ...)` frame. The string is the verbatim wire bytes.
    Reply(String),
    /// A dialect push that installed cleanly into the daemon cache.
    PushInstalled {
        name: String,
        define_form: String,
        digest: String,
        frame: String,
    },
    /// A dialect push whose `(define ...)` failed R1–R5; the cache rejected
    /// it. The waiter should treat this as an upstream protocol error
    /// rather than a successful query result.
    PushInstallFailed {
        name: String,
        reason: String,
        frame: String,
    },
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct RecvWaiterId(u64);

#[derive(Debug)]
struct RecvWaiterGuard {
    store: AgentStore,
    handle: AgentHandle,
    waiter_id: RecvWaiterId,
    armed: bool,
}

#[derive(Debug)]
enum RecvClaim {
    Ready(String),
    Waiting {
        notify: Arc<Notify>,
        waiter: RecvWaiterGuard,
    },
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct QueuedMessage {
    text: String,
    bytes: usize,
}

pub const DAEMON_LOCK_FILE: &str = "daemon.lock";
pub const DAEMON_DISCOVERY_FILE: &str = "daemon.json";
const DAEMON_TOKEN_BYTES: usize = 32;
const CROCKFORD_BASE32: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const AGENT_HANDLE_BYTES: usize = 16;
const AGENT_HANDLE_LEN: usize = 26;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RuntimePaths {
    pub runtime_dir: PathBuf,
    pub lock_file: PathBuf,
    pub discovery_file: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct DiscoveryRecord {
    pub pid: u32,
    pub addr: SocketAddr,
    pub token: String,
    #[serde(with = "time::serde::rfc3339")]
    pub started_at: OffsetDateTime,
    pub version: String,
    pub api_version: u16,
}

#[derive(Debug)]
pub struct DaemonLock {
    _file: File,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum DiscoveryState {
    Missing,
    Live {
        record: DiscoveryRecord,
        ping: PingResponse,
    },
    StaleLockFree {
        record: DiscoveryRecord,
    },
    StaleLockHeld {
        record: DiscoveryRecord,
    },
    AuthFailure {
        record: DiscoveryRecord,
    },
    ApiIncompatible {
        record: DiscoveryRecord,
        daemon_version: Option<String>,
        daemon_api_version: Option<u16>,
        cli_api_version: u16,
    },
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ProbeResult {
    Live(PingResponse),
    AuthFailure,
    NoResponse,
}

#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    #[error("failed to resolve per-user runtime directory")]
    RuntimeDirUnavailable,
    #[error("runtime path is not secure: {path}: {reason}")]
    InsecurePath { path: PathBuf, reason: String },
    #[error("failed to read discovery record: {0}")]
    ReadDiscovery(#[from] io::Error),
    #[error("failed to parse discovery record: {0}")]
    ParseDiscovery(#[from] serde_json::Error),
    #[error("failed to create authorization header: {0}")]
    InvalidAuthHeader(#[from] reqwest::header::InvalidHeaderValue),
}

impl RuntimePaths {
    pub fn new(runtime_dir: PathBuf) -> Self {
        Self {
            lock_file: runtime_dir.join(DAEMON_LOCK_FILE),
            discovery_file: runtime_dir.join(DAEMON_DISCOVERY_FILE),
            runtime_dir,
        }
    }
}

impl AgentHandle {
    pub fn new(value: impl Into<String>) -> Result<Self, AgentError> {
        let value = value.into();
        if is_valid_agent_handle(&value) {
            Ok(Self(value))
        } else {
            Err(AgentError::MalformedHandle)
        }
    }

    pub fn generate() -> Self {
        loop {
            let mut bytes = [0_u8; AGENT_HANDLE_BYTES];
            OsRng
                .try_fill_bytes(&mut bytes)
                .expect("OS random generator should be available");
            let encoded = encode_crockford_base32_128(bytes);
            if let Ok(handle) = Self::new(encoded) {
                return handle;
            }
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for AgentHandle {
    type Error = AgentError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<AgentHandle> for String {
    fn from(value: AgentHandle) -> Self {
        value.0
    }
}

impl AgentStoreConfig {
    pub fn from_config(config: &crate::config::AppConfig) -> Self {
        Self {
            agent_id_prefix: config.agent.agent_id_prefix.clone(),
            max_messages_per_handle: config.daemon.max_messages_per_handle,
            max_bytes_per_handle: config.daemon.max_bytes_per_handle,
        }
    }
}

impl AgentStore {
    pub fn new(config: AgentStoreConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(AgentRegistry {
                config,
                agents: HashMap::new(),
                active: None,
            })),
        }
    }

    pub fn validate_advertisement(dialects: &[String]) -> Result<(), AgentError> {
        validate_agent_advertisement(dialects)
    }

    pub async fn insert_connected(
        &self,
        handle: AgentHandle,
        dialects: Vec<String>,
    ) -> Result<AgentStatusSnapshot, AgentError> {
        self.insert_connected_with_close_signal(handle, dialects, None)
            .await
    }

    pub async fn insert_connected_with_close_signal(
        &self,
        handle: AgentHandle,
        dialects: Vec<String>,
        close_tx: Option<oneshot::Sender<()>>,
    ) -> Result<AgentStatusSnapshot, AgentError> {
        self.insert_connected_with_router_channels(handle, dialects, close_tx, None, None, None)
            .await
    }

    pub async fn insert_connected_with_router_channels(
        &self,
        handle: AgentHandle,
        dialects: Vec<String>,
        close_tx: Option<oneshot::Sender<()>>,
        send_channel: Option<AgentSendChannel>,
        wire_id: Option<String>,
        channel: Option<String>,
    ) -> Result<AgentStatusSnapshot, AgentError> {
        validate_agent_advertisement(&dialects)?;
        let mut inner = self.inner.lock().await;
        // The router derives an upstream id from the local handle; the chat
        // transport supplies its own `@handle` (its identity on the hub), so
        // status reports the real wire identity for each transport.
        let router_agent_id = wire_id
            .unwrap_or_else(|| format!("{}-{}", inner.config.agent_id_prefix, handle.as_str()));
        let entry = AgentEntry {
            router_agent_id,
            dialects,
            state: AgentState::Connected,
            unhealthy_reason: None,
            unhealthy_detail: None,
            reconnect_attempts: 0,
            reconnect_detail: None,
            queue: VecDeque::new(),
            queued_bytes: 0,
            recv_waiter: None,
            next_recv_waiter_id: 0,
            notify: Arc::new(Notify::new()),
            close_tx,
            send_channel,
            pending_meta_reply: None,
            store: Arc::new(Mutex::new(ThreadedMessageStore::new())),
            send_sequencer: Arc::new(Mutex::new(())),
            dialect_cache: DialectCache::new(),
            channel,
        };
        inner.agents.insert(handle.clone(), entry);
        // The newest agent becomes the session's active handle (REQ-003).
        inner.active = Some(handle.clone());
        Ok(inner
            .agents
            .get(&handle)
            .expect("agent was just inserted")
            .snapshot(&handle))
    }

    /// The session's active handle: the most recently created, still-open
    /// agent. `None` when no agent is open (or the active one was closed).
    pub async fn active_handle(&self) -> Option<AgentHandle> {
        self.inner.lock().await.active.clone()
    }

    pub async fn send_outbound(
        &self,
        handle: &AgentHandle,
        message: String,
    ) -> Result<(), AgentError> {
        let send_channel = {
            let inner = self.inner.lock().await;
            let entry = inner.agents.get(handle).ok_or(AgentError::UnknownHandle)?;
            entry.ensure_healthy()?;
            match entry.send_channel.clone() {
                Some(channel) => channel,
                // SPEC-026 REQ-004/REQ-008: an agent still coming up after a
                // daemon restart has no transport to hand the frame to *yet*.
                // That is the retryable case, not the dead one — the caller
                // re-offers and it lands once the join completes.
                None if entry.state == AgentState::Reconnecting => {
                    return Err(AgentError::NotReady {
                        detail: entry.reconnect_detail.clone(),
                    });
                }
                None => {
                    return Err(AgentError::Unhealthy {
                        reason: "local_send_failed".to_owned(),
                        detail: Some("agent has no router send channel".to_owned()),
                    });
                }
            }
        };

        let (result_tx, result_rx) = oneshot::channel();
        if send_channel
            .tx
            .send(OutboundFrame { message, result_tx })
            .await
            .is_err()
        {
            let _ = self
                .mark_unhealthy(
                    handle,
                    "local_send_failed",
                    Some("router send loop is closed".to_owned()),
                )
                .await;
            return Err(AgentError::Unhealthy {
                reason: "local_send_failed".to_owned(),
                detail: Some("router send loop is closed".to_owned()),
            });
        }

        match result_rx.await {
            Ok(Ok(())) => Ok(()),
            // A transient precondition (MLS membership not yet established):
            // leave the handle healthy so the next attempt — once the Welcome
            // lands — can succeed. Marking it unhealthy here would strand the
            // handle over a membership race (SPEC-013 REQ-023).
            Ok(Err(reject)) if reject.retryable => Err(AgentError::NotReady {
                detail: Some(reject.detail),
            }),
            Ok(Err(reject)) => {
                let _ = self
                    .mark_unhealthy(handle, "local_send_failed", Some(reject.detail.clone()))
                    .await;
                Err(AgentError::Unhealthy {
                    reason: "local_send_failed".to_owned(),
                    detail: Some(reject.detail),
                })
            }
            Err(_) => {
                let detail = "router send loop dropped send result".to_owned();
                let _ = self
                    .mark_unhealthy(handle, "local_send_failed", Some(detail.clone()))
                    .await;
                Err(AgentError::Unhealthy {
                    reason: "local_send_failed".to_owned(),
                    detail: Some(detail),
                })
            }
        }
    }

    /// Send a meta frame to the router and await the next reply frame for
    /// this agent. The receive loop calls [`try_route_meta_reply`] before
    /// forwarding inbound frames to the recv queue — if a pending sender
    /// is registered here, that frame is routed to it instead.
    ///
    /// Single-slot per agent: a concurrent call while another meta send is
    /// in flight returns `MetaSendBusy` rather than queuing.
    pub async fn send_meta_and_await(
        &self,
        handle: &AgentHandle,
        message: String,
        expectation: MetaReplyExpectation,
        timeout: Duration,
    ) -> Result<MetaReplyDelivery, AgentError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        {
            let mut inner = self.inner.lock().await;
            let entry = inner
                .agents
                .get_mut(handle)
                .ok_or(AgentError::UnknownHandle)?;
            entry.ensure_healthy()?;
            if entry.pending_meta_reply.is_some() {
                return Err(AgentError::MetaSendBusy);
            }
            entry.pending_meta_reply = Some(PendingMetaReply {
                expectation,
                sender: reply_tx,
            });
        }

        if let Err(error) = self.send_outbound(handle, message).await {
            // Clear the slot so subsequent attempts aren't stuck on the
            // bookkeeping. Best-effort: if the handle vanished mid-flight
            // the next get_mut will simply miss.
            let mut inner = self.inner.lock().await;
            if let Some(entry) = inner.agents.get_mut(handle) {
                entry.pending_meta_reply = None;
            }
            return Err(error);
        }

        match tokio::time::timeout(timeout, reply_rx).await {
            Ok(Ok(delivery)) => Ok(delivery),
            Ok(Err(_recv)) => {
                // Sender dropped without sending — happens if the receive
                // loop exited or `mark_unhealthy` cleared the slot while we
                // were awaiting. Surface as unhealthy so meta callers fail
                // fast on a closed/dead connection instead of waiting out
                // the full timeout.
                Err(AgentError::Unhealthy {
                    reason: "meta_reply_channel_closed".to_owned(),
                    detail: Some("router connection closed before meta reply arrived".to_owned()),
                })
            }
            Err(_elapsed) => {
                // Timed out — clear the slot so the next attempt can proceed.
                let mut inner = self.inner.lock().await;
                if let Some(entry) = inner.agents.get_mut(handle) {
                    entry.pending_meta_reply = None;
                }
                Err(AgentError::MetaReplyTimeout)
            }
        }
    }

    /// Hook for the router receive loop. If a meta-reply slot is filled
    /// for this agent AND the pending caller's expectation matches the
    /// classified inbound, deliver and return `None` (the frame is
    /// consumed; do not forward to the recv queue). If no waiter is
    /// registered, or the waiter is expecting a different shape (e.g.
    /// awaiting a `Reply` while an unsolicited subscription push arrived),
    /// return `Some(frame)` so the caller can fall through to
    /// `enqueue_inbound` and the awaited reply isn't stolen by an
    /// unrelated push.
    pub async fn try_route_meta_reply(
        &self,
        handle: &AgentHandle,
        delivery: MetaReplyDelivery,
    ) -> Option<String> {
        let mut inner = self.inner.lock().await;
        let Some(entry) = inner.agents.get_mut(handle) else {
            return Some(delivery.frame().to_owned());
        };
        let matches = entry
            .pending_meta_reply
            .as_ref()
            .is_some_and(|pending| expectation_matches(&pending.expectation, &delivery));
        if !matches {
            return Some(delivery.frame().to_owned());
        }
        // Safe to unwrap: we just verified `is_some_and` above and still
        // hold the lock so no other task can take it.
        let pending = entry
            .pending_meta_reply
            .take()
            .expect("pending meta waiter taken under lock after match check");
        match pending.sender.send(delivery) {
            Ok(()) => None,
            // Receiver dropped (caller timed out / cancelled) — the frame
            // becomes orphaned. Drop it rather than queueing, since the
            // caller no longer wants it.
            Err(_returned) => None,
        }
    }

    pub async fn enqueue_inbound(
        &self,
        handle: &AgentHandle,
        message: String,
    ) -> Result<(), AgentError> {
        let mut inner = self.inner.lock().await;
        let max_messages = inner.config.max_messages_per_handle;
        let max_bytes = inner.config.max_bytes_per_handle;
        let entry = inner
            .agents
            .get_mut(handle)
            .ok_or(AgentError::UnknownHandle)?;
        entry.ensure_healthy()?;
        let bytes = message.len();

        if entry.queue.len() >= max_messages || entry.queued_bytes.saturating_add(bytes) > max_bytes
        {
            entry.mark_unhealthy("queue_overflow", None);
            entry.close_connection();
            entry.notify.notify_waiters();
            return Err(AgentError::QueueOverflow);
        }

        entry.queue.push_back(QueuedMessage {
            text: message,
            bytes,
        });
        entry.queued_bytes += bytes;
        entry.notify.notify_one();
        Ok(())
    }

    pub async fn recv(
        &self,
        handle: &AgentHandle,
        timeout: Option<Duration>,
    ) -> Result<String, AgentError> {
        let (notify, mut waiter) = match self.claim_recv_waiter(handle).await? {
            RecvClaim::Ready(message) => return Ok(message),
            RecvClaim::Waiting { notify, waiter } => (notify, waiter),
        };
        let waiter_id = waiter.waiter_id;

        let wait = async {
            loop {
                notify.notified().await;
                let mut inner = self.inner.lock().await;
                let Some(entry) = inner.agents.get_mut(handle) else {
                    waiter.disarm();
                    return Err(AgentError::UnknownHandle);
                };
                if let Err(error) = entry.ensure_healthy() {
                    entry.clear_recv_waiter_if_match(waiter_id);
                    waiter.disarm();
                    return Err(error);
                }
                if let Some(message) = entry.pop_message() {
                    entry.clear_recv_waiter_if_match(waiter_id);
                    waiter.disarm();
                    return Ok(message);
                }
            }
        };

        match timeout {
            Some(timeout) => match tokio::time::timeout(timeout, wait).await {
                Ok(result) => result,
                Err(_) => {
                    self.clear_waiter_if_match(handle, waiter_id).await;
                    waiter.disarm();
                    Err(AgentError::RecvTimeout)
                }
            },
            None => wait.await,
        }
    }

    pub async fn close(&self, handle: &AgentHandle) -> Result<(), AgentError> {
        let notify = {
            let mut inner = self.inner.lock().await;
            let entry = inner
                .agents
                .remove(handle)
                .ok_or(AgentError::UnknownHandle)?;
            if inner.active.as_ref() == Some(handle) {
                inner.active = None;
            }
            let mut entry = entry;
            entry.close_connection();
            entry.notify
        };
        notify.notify_waiters();
        Ok(())
    }

    pub async fn mark_unhealthy(
        &self,
        handle: &AgentHandle,
        reason: impl Into<String>,
        detail: Option<String>,
    ) -> Result<(), AgentError> {
        let mut inner = self.inner.lock().await;
        let entry = inner
            .agents
            .get_mut(handle)
            .ok_or(AgentError::UnknownHandle)?;
        entry.mark_unhealthy(reason, detail);
        entry.close_connection();
        entry.notify.notify_waiters();
        Ok(())
    }

    /// SPEC-026 REQ-001 / CON-003: the agent's socket ended at the transport
    /// level and the transport loop is re-establishing it.
    ///
    /// Deliberately *unlike* [`Self::mark_unhealthy`]: it does not close the
    /// connection and does not drop a pending meta waiter. The session task is
    /// still alive and still owns the close signal — tearing that down would
    /// leave a `hark close` during an outage with nothing to signal.
    pub async fn mark_reconnecting(
        &self,
        handle: &AgentHandle,
        attempts: u32,
        detail: Option<String>,
    ) -> Result<(), AgentError> {
        let mut inner = self.inner.lock().await;
        let entry = inner
            .agents
            .get_mut(handle)
            .ok_or(AgentError::UnknownHandle)?;
        entry.state = AgentState::Reconnecting;
        entry.reconnect_attempts = attempts;
        entry.reconnect_detail = detail;
        Ok(())
    }

    /// SPEC-026 REQ-008: register an agent that is being re-established after a
    /// daemon restart but has not reached the hub yet.
    ///
    /// It exists so that "the hub was down when I rebooted" is a *visible,
    /// self-healing* state rather than a missing agent. Without it, an operator
    /// restarting into a hub outage would see `agents: 0` — indistinguishable
    /// from having lost the pairing, which is the failure being fixed.
    ///
    /// The entry carries no send channel and no close signal; those arrive with
    /// the connection. A send against it is refused *retryably*, like any other
    /// send during a gap.
    pub async fn insert_reconnecting(
        &self,
        handle: AgentHandle,
        dialects: Vec<String>,
        wire_id: String,
        channel: Option<String>,
        detail: Option<String>,
    ) -> Result<AgentStatusSnapshot, AgentError> {
        validate_agent_advertisement(&dialects)?;
        let mut inner = self.inner.lock().await;
        let entry = AgentEntry {
            router_agent_id: wire_id,
            dialects,
            state: AgentState::Reconnecting,
            unhealthy_reason: None,
            unhealthy_detail: None,
            reconnect_attempts: 0,
            reconnect_detail: detail,
            queue: VecDeque::new(),
            queued_bytes: 0,
            recv_waiter: None,
            next_recv_waiter_id: 0,
            notify: Arc::new(Notify::new()),
            close_tx: None,
            send_channel: None,
            pending_meta_reply: None,
            store: Arc::new(Mutex::new(ThreadedMessageStore::new())),
            send_sequencer: Arc::new(Mutex::new(())),
            dialect_cache: DialectCache::new(),
            channel,
        };
        inner.agents.insert(handle.clone(), entry);
        inner.active = Some(handle.clone());
        Ok(inner
            .agents
            .get(&handle)
            .expect("agent was just inserted")
            .snapshot(&handle))
    }

    /// SPEC-026 REQ-001 / CON-003: the socket is back. Clears the reconnect
    /// progress so the next outage is reported from zero.
    ///
    /// Only a reconnecting handle recovers this way. A handle already marked
    /// [`AgentState::Unhealthy`] stays unhealthy: those transitions are terminal
    /// by construction (REQ-005), and silently reviving one would let a hub
    /// rejection be papered over by a later successful connect.
    pub async fn mark_connected(&self, handle: &AgentHandle) -> Result<(), AgentError> {
        let mut inner = self.inner.lock().await;
        let entry = inner
            .agents
            .get_mut(handle)
            .ok_or(AgentError::UnknownHandle)?;
        if entry.state == AgentState::Unhealthy {
            return entry.ensure_healthy();
        }
        entry.state = AgentState::Connected;
        entry.reconnect_attempts = 0;
        entry.reconnect_detail = None;
        Ok(())
    }

    pub async fn status_snapshots(&self) -> Vec<AgentStatusSnapshot> {
        let inner = self.inner.lock().await;
        let mut snapshots = inner
            .agents
            .iter()
            .map(|(handle, entry)| entry.snapshot(handle))
            .collect::<Vec<_>>();
        snapshots.sort_by(|left, right| left.agent_handle.cmp(&right.agent_handle));
        snapshots
    }

    async fn claim_recv_waiter(&self, handle: &AgentHandle) -> Result<RecvClaim, AgentError> {
        let mut inner = self.inner.lock().await;
        let entry = inner
            .agents
            .get_mut(handle)
            .ok_or(AgentError::UnknownHandle)?;
        entry.ensure_healthy()?;
        if let Some(message) = entry.pop_message() {
            return Ok(RecvClaim::Ready(message));
        }
        if entry.recv_waiter.is_some() {
            return Err(AgentError::RecvAlreadyWaiting);
        }
        let waiter_id = entry.allocate_recv_waiter_id();
        entry.recv_waiter = Some(waiter_id);
        Ok(RecvClaim::Waiting {
            notify: Arc::clone(&entry.notify),
            waiter: RecvWaiterGuard {
                store: self.clone(),
                handle: handle.clone(),
                waiter_id,
                armed: true,
            },
        })
    }

    async fn clear_waiter_if_match(&self, handle: &AgentHandle, waiter_id: RecvWaiterId) {
        let mut inner = self.inner.lock().await;
        if let Some(entry) = inner.agents.get_mut(handle) {
            entry.clear_recv_waiter_if_match(waiter_id);
        }
    }

    /// Borrow the per-handle causal message store (R5 Phase A plumbing).
    ///
    /// Returns an `Arc<Mutex<_>>` cloned out from `AgentEntry` so the
    /// caller can lock it independently of the `AgentRegistry` mutex.
    /// This is the entry point Phase B/C will use to feed the pipeline.
    pub async fn store_handle(
        &self,
        handle: &AgentHandle,
    ) -> Result<Arc<Mutex<ThreadedMessageStore>>, AgentError> {
        let inner = self.inner.lock().await;
        let entry = inner.agents.get(handle).ok_or(AgentError::UnknownHandle)?;
        Ok(Arc::clone(&entry.store))
    }

    /// Clone out the per-handle send sequencer mutex. Held by the
    /// local-API `/send` handler for the duration of (validate, append,
    /// enqueue) so concurrent senders on this handle agree on the wire
    /// order matching their store-append order. Never taken by the
    /// router receive loop — taking it there would re-introduce the
    /// inbound-vs-outbound deadlock this sequencer was added to avoid.
    pub async fn send_sequencer(&self, handle: &AgentHandle) -> Result<Arc<Mutex<()>>, AgentError> {
        let inner = self.inner.lock().await;
        let entry = inner.agents.get(handle).ok_or(AgentError::UnknownHandle)?;
        Ok(Arc::clone(&entry.send_sequencer))
    }

    /// Clone out the per-agent dialect cache. Cheap (`Arc<RwLock<_>>`
    /// internally). R5 Phase B: callers use this to snapshot the
    /// `DialectRegistry` for `run_pipeline_full`.
    pub async fn dialect_cache_handle(
        &self,
        handle: &AgentHandle,
    ) -> Result<DialectCache, AgentError> {
        let inner = self.inner.lock().await;
        let entry = inner.agents.get(handle).ok_or(AgentError::UnknownHandle)?;
        Ok(entry.dialect_cache.clone())
    }

    /// Append a message into a handle's causal store. Returns `Ok(true)`
    /// if newly inserted, `Ok(false)` if deduplicated (REQ-310).
    pub async fn append_message(
        &self,
        handle: &AgentHandle,
        hash: ContentHash,
        thread: ThreadId,
        message: Message,
    ) -> Result<bool, AgentError> {
        let store = self.store_handle(handle).await?;
        let mut guard = store.lock().await;
        Ok(guard.append(hash, thread, message))
    }

    /// Look up a message by content hash across all threads of this
    /// handle's store. Clones the message because the lock can't be held
    /// across the await boundary by callers.
    pub async fn lookup_message(
        &self,
        handle: &AgentHandle,
        hash: &ContentHash,
    ) -> Result<Option<Message>, AgentError> {
        let store = self.store_handle(handle).await?;
        let guard = store.lock().await;
        Ok(guard.lookup(hash).cloned())
    }
}

impl AgentSendChannel {
    pub fn new(tx: mpsc::Sender<OutboundFrame>) -> Self {
        Self { tx }
    }
}

impl MetaReplyDelivery {
    fn frame(&self) -> &str {
        match self {
            MetaReplyDelivery::Reply(frame)
            | MetaReplyDelivery::PushInstalled { frame, .. }
            | MetaReplyDelivery::PushInstallFailed { frame, .. } => frame,
        }
    }

    pub fn frame_owned(self) -> String {
        match self {
            MetaReplyDelivery::Reply(frame)
            | MetaReplyDelivery::PushInstalled { frame, .. }
            | MetaReplyDelivery::PushInstallFailed { frame, .. } => frame,
        }
    }
}

fn expectation_matches(expectation: &MetaReplyExpectation, delivery: &MetaReplyDelivery) -> bool {
    match (expectation, delivery) {
        (_, MetaReplyDelivery::Reply(_)) => true,
        (MetaReplyExpectation::Reply, _) => false,
        (
            MetaReplyExpectation::ReplyOrPushNamed(expected),
            MetaReplyDelivery::PushInstalled { name, .. }
            | MetaReplyDelivery::PushInstallFailed { name, .. },
        ) => expected == name,
    }
}

impl AgentEntry {
    fn allocate_recv_waiter_id(&mut self) -> RecvWaiterId {
        let waiter_id = RecvWaiterId(self.next_recv_waiter_id);
        self.next_recv_waiter_id = self.next_recv_waiter_id.wrapping_add(1);
        waiter_id
    }

    fn clear_recv_waiter_if_match(&mut self, waiter_id: RecvWaiterId) {
        if self.recv_waiter == Some(waiter_id) {
            self.recv_waiter = None;
        }
    }

    fn ensure_healthy(&self) -> Result<(), AgentError> {
        if self.state == AgentState::Unhealthy {
            Err(AgentError::Unhealthy {
                reason: self
                    .unhealthy_reason
                    .clone()
                    .unwrap_or_else(|| "unknown".to_owned()),
                detail: self.unhealthy_detail.clone(),
            })
        } else {
            Ok(())
        }
    }

    fn pop_message(&mut self) -> Option<String> {
        let message = self.queue.pop_front()?;
        self.queued_bytes = self.queued_bytes.saturating_sub(message.bytes);
        Some(message.text)
    }

    fn mark_unhealthy(&mut self, reason: impl Into<String>, detail: Option<String>) {
        self.state = AgentState::Unhealthy;
        self.unhealthy_reason = Some(reason.into());
        self.unhealthy_detail = detail;
        // Terminal wins over "coming back": a handle that died mid-outage
        // reports why it died, not how many times it had tried (SPEC-026
        // CON-003 — the two field pairs never both carry meaning).
        self.reconnect_attempts = 0;
        self.reconnect_detail = None;
        // Drop any pending meta waiter on every unhealthy path — including
        // `enqueue_inbound`'s queue-overflow case, which calls us directly
        // without going through `AgentStore::mark_unhealthy`. Without this,
        // a full inbound queue (now reachable when unrelated subscription
        // pushes fall through) can close the connection while a
        // publish/list/query waiter stays armed until META_REPLY_TIMEOUT.
        self.pending_meta_reply = None;
    }

    fn close_connection(&mut self) {
        if let Some(close_tx) = self.close_tx.take() {
            let _ = close_tx.send(());
        }
    }

    fn snapshot(&self, handle: &AgentHandle) -> AgentStatusSnapshot {
        AgentStatusSnapshot {
            agent_handle: handle.as_str().to_owned(),
            router_agent_id: self.router_agent_id.clone(),
            dialects: self.dialects.clone(),
            state: self.state,
            queued_messages: self.queue.len(),
            queued_bytes: self.queued_bytes,
            unhealthy_reason: self.unhealthy_reason.clone(),
            unhealthy_detail: self.unhealthy_detail.clone(),
            channel: self.channel.clone(),
            reconnect_attempts: self.reconnect_attempts,
            reconnect_detail: self.reconnect_detail.clone(),
        }
    }
}

impl RecvWaiterGuard {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for RecvWaiterGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let store = self.store.clone();
        let handle = self.handle.clone();
        let waiter_id = self.waiter_id;
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                store.clear_waiter_if_match(&handle, waiter_id).await;
            });
        }
    }
}

impl DiscoveryRecord {
    pub fn current(addr: SocketAddr, token: String) -> Self {
        Self {
            pid: std::process::id(),
            addr,
            token,
            started_at: OffsetDateTime::now_utc(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            api_version: LOCAL_API_VERSION,
        }
    }
}

pub fn is_valid_agent_handle(value: &str) -> bool {
    value.len() == AGENT_HANDLE_LEN
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'A'..=b'H' | b'J'..=b'K' | b'M'..=b'N' | b'P'..=b'T' | b'V'..=b'Z'))
}

fn validate_agent_advertisement(dialects: &[String]) -> Result<(), AgentError> {
    // An empty advertisement is allowed: "advertise nothing" (SPEC-016 HP-2,
    // `hark join` without `--speak`). `hark init` still requires at least one
    // dialect at the CLI layer.
    let mut seen = std::collections::HashSet::new();
    for dialect in dialects {
        validate_dialect_id(dialect)
            .map_err(|error| AgentError::InvalidDialect(error.to_string()))?;
        if !seen.insert(dialect) {
            return Err(AgentError::DuplicateDialect);
        }
    }

    Ok(())
}

fn encode_crockford_base32_128(bytes: [u8; AGENT_HANDLE_BYTES]) -> String {
    let mut output = String::with_capacity(AGENT_HANDLE_LEN);
    let mut buffer = 0_u16;
    let mut bits = 0_u8;

    for byte in bytes {
        buffer = (buffer << 8) | u16::from(byte);
        bits += 8;
        while bits >= 5 {
            let shift = bits - 5;
            let index = ((buffer >> shift) & 0b1_1111) as usize;
            output.push(CROCKFORD_BASE32[index] as char);
            bits -= 5;
            buffer &= (1_u16 << bits) - 1;
        }
    }

    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0b1_1111) as usize;
        output.push(CROCKFORD_BASE32[index] as char);
    }

    debug_assert_eq!(output.len(), AGENT_HANDLE_LEN);
    output
}

pub fn resolve_runtime_paths() -> Result<RuntimePaths, DiscoveryError> {
    Ok(RuntimePaths::new(default_runtime_dir()?))
}

pub fn create_runtime_dir(runtime_dir: &Path) -> Result<(), DiscoveryError> {
    if runtime_dir.exists() {
        ensure_secure_path(runtime_dir, SecurePathKind::Directory)?;
        return Ok(());
    }

    create_dir_owner_only(runtime_dir)?;
    ensure_secure_path(runtime_dir, SecurePathKind::Directory)
}

pub fn acquire_daemon_lock(paths: &RuntimePaths) -> Result<DaemonLock, DiscoveryError> {
    ensure_secure_path(&paths.runtime_dir, SecurePathKind::Directory)?;
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&paths.lock_file)?;
    set_owner_only_file_permissions(&paths.lock_file)?;
    ensure_secure_path(&paths.lock_file, SecurePathKind::File)?;
    file.try_lock_exclusive()?;
    Ok(DaemonLock { _file: file })
}

pub fn probe_lock_available(paths: &RuntimePaths) -> Result<bool, DiscoveryError> {
    match acquire_daemon_lock(paths) {
        Ok(_lock) => Ok(true),
        Err(DiscoveryError::ReadDiscovery(error)) if error.kind() == io::ErrorKind::WouldBlock => {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

pub fn write_discovery_record(
    paths: &RuntimePaths,
    record: &DiscoveryRecord,
) -> Result<(), DiscoveryError> {
    ensure_secure_path(&paths.runtime_dir, SecurePathKind::Directory)?;
    let temp_file = paths.discovery_file.with_extension("json.tmp");
    let json = serde_json::to_vec_pretty(record)?;

    {
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temp_file)?;
        set_owner_only_file_permissions(&temp_file)?;
        file.write_all(&json)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
    }

    fs::rename(&temp_file, &paths.discovery_file)?;
    set_owner_only_file_permissions(&paths.discovery_file)?;
    ensure_secure_path(&paths.discovery_file, SecurePathKind::File)
}

pub fn load_discovery_record(
    paths: &RuntimePaths,
) -> Result<Option<DiscoveryRecord>, DiscoveryError> {
    match paths.discovery_file.try_exists() {
        Ok(true) => {
            ensure_secure_path(&paths.discovery_file, SecurePathKind::File)?;
            let bytes = fs::read(&paths.discovery_file)?;
            Ok(Some(serde_json::from_slice(&bytes)?))
        }
        Ok(false) => Ok(None),
        Err(error) => Err(DiscoveryError::ReadDiscovery(error)),
    }
}

pub fn generate_daemon_token() -> String {
    let mut bytes = [0_u8; DAEMON_TOKEN_BYTES];
    OsRng
        .try_fill_bytes(&mut bytes)
        .expect("OS random generator should be available");
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn authenticated_headers(record: &DiscoveryRecord) -> Result<HeaderMap, DiscoveryError> {
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", record.token))?,
    );
    Ok(headers)
}

pub fn classify_discovery_with_probe(
    paths: &RuntimePaths,
    probe: impl FnOnce(&DiscoveryRecord) -> ProbeResult,
) -> Result<DiscoveryState, DiscoveryError> {
    let Some(record) = load_discovery_record(paths)? else {
        return Ok(DiscoveryState::Missing);
    };

    match probe(&record) {
        ProbeResult::Live(ping) if ping.api_version == LOCAL_API_VERSION => {
            Ok(DiscoveryState::Live { record, ping })
        }
        ProbeResult::Live(ping) => Ok(DiscoveryState::ApiIncompatible {
            record,
            daemon_version: Some(ping.version),
            daemon_api_version: Some(ping.api_version),
            cli_api_version: LOCAL_API_VERSION,
        }),
        ProbeResult::AuthFailure => Ok(DiscoveryState::AuthFailure { record }),
        ProbeResult::NoResponse => {
            if probe_lock_available(paths)? {
                Ok(DiscoveryState::StaleLockFree { record })
            } else {
                Ok(DiscoveryState::StaleLockHeld { record })
            }
        }
    }
}

fn default_runtime_dir() -> Result<PathBuf, DiscoveryError> {
    #[cfg(target_os = "linux")]
    {
        if let Some(xdg_runtime_dir) = std::env::var_os("XDG_RUNTIME_DIR") {
            return Ok(PathBuf::from(xdg_runtime_dir).join(crate::constants::COMMAND_NAME));
        }
    }

    let base_dirs = BaseDirs::new().ok_or(DiscoveryError::RuntimeDirUnavailable)?;

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    {
        Ok(base_dirs
            .data_local_dir()
            .join(crate::constants::COMMAND_NAME)
            .join("runtime"))
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        Ok(base_dirs
            .state_dir()
            .unwrap_or_else(|| base_dirs.data_local_dir())
            .join(crate::constants::COMMAND_NAME)
            .join("runtime"))
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum SecurePathKind {
    Directory,
    File,
}

#[cfg(unix)]
fn create_dir_owner_only(path: &Path) -> Result<(), DiscoveryError> {
    use std::os::unix::fs::DirBuilderExt;

    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)?;
    Ok(())
}

#[cfg(not(unix))]
fn create_dir_owner_only(path: &Path) -> Result<(), DiscoveryError> {
    fs::create_dir_all(path)?;
    Ok(())
}

#[cfg(unix)]
fn set_owner_only_file_permissions(path: &Path) -> Result<(), DiscoveryError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_owner_only_file_permissions(_path: &Path) -> Result<(), DiscoveryError> {
    Ok(())
}

#[cfg(unix)]
fn ensure_secure_path(path: &Path, kind: SecurePathKind) -> Result<(), DiscoveryError> {
    use std::os::unix::fs::MetadataExt;

    let symlink_metadata = fs::symlink_metadata(path)?;
    if symlink_metadata.file_type().is_symlink() {
        return Err(DiscoveryError::InsecurePath {
            path: path.to_path_buf(),
            reason: "path must not be a symlink".to_owned(),
        });
    }

    let metadata = fs::metadata(path)?;
    let kind_matches = match kind {
        SecurePathKind::Directory => metadata.is_dir(),
        SecurePathKind::File => metadata.is_file(),
    };
    if !kind_matches {
        return Err(DiscoveryError::InsecurePath {
            path: path.to_path_buf(),
            reason: format!("path must be a {kind:?}"),
        });
    }

    if metadata.uid() != current_uid() {
        return Err(DiscoveryError::InsecurePath {
            path: path.to_path_buf(),
            reason: "path must be owned by the current user".to_owned(),
        });
    }

    if metadata.mode() & 0o077 != 0 {
        return Err(DiscoveryError::InsecurePath {
            path: path.to_path_buf(),
            reason: "path must not be accessible by group or other users".to_owned(),
        });
    }

    Ok(())
}

#[cfg(not(unix))]
fn ensure_secure_path(path: &Path, kind: SecurePathKind) -> Result<(), DiscoveryError> {
    let metadata = fs::metadata(path)?;
    let kind_matches = match kind {
        SecurePathKind::Directory => metadata.is_dir(),
        SecurePathKind::File => metadata.is_file(),
    };

    if kind_matches {
        Ok(())
    } else {
        Err(DiscoveryError::InsecurePath {
            path: path.to_path_buf(),
            reason: format!("path must be a {kind:?}"),
        })
    }
}

#[cfg(unix)]
fn current_uid() -> u32 {
    unsafe { libc_getuid() }
}

#[cfg(unix)]
unsafe fn libc_getuid() -> u32 {
    unsafe extern "C" {
        fn getuid() -> u32;
    }

    unsafe { getuid() }
}

#[cfg(test)]
mod tests {
    use std::{fs, net::SocketAddr};

    use tempfile::TempDir;
    use time::OffsetDateTime;

    use crate::{constants::LOCAL_API_VERSION, local_api::PingResponse};

    use super::{
        DAEMON_DISCOVERY_FILE, DiscoveryError, DiscoveryRecord, DiscoveryState, ProbeResult,
        RuntimePaths, acquire_daemon_lock, authenticated_headers, classify_discovery_with_probe,
        create_runtime_dir, generate_daemon_token, load_discovery_record, probe_lock_available,
        write_discovery_record,
    };

    #[test]
    fn creates_runtime_directory_with_owner_only_permissions() {
        let temp_dir = TempDir::new().expect("temp dir should be created");
        let runtime_dir = temp_dir.path().join("runtime");

        create_runtime_dir(&runtime_dir).expect("runtime dir should be created");

        assert!(runtime_dir.is_dir());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mode = fs::metadata(&runtime_dir)
                .expect("metadata should load")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o700);
        }
    }

    #[test]
    fn writes_and_loads_discovery_record_atomically_with_owner_only_permissions() {
        let temp_dir = TempDir::new().expect("temp dir should be created");
        let paths = runtime_paths(temp_dir.path());
        create_runtime_dir(&paths.runtime_dir).expect("runtime dir should be created");
        let record = sample_record(LOCAL_API_VERSION);

        write_discovery_record(&paths, &record).expect("discovery should be written");
        let loaded = load_discovery_record(&paths)
            .expect("discovery should load")
            .expect("discovery should exist");

        assert_eq!(loaded, record);
        assert!(!paths.discovery_file.with_extension("json.tmp").exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mode = fs::metadata(&paths.discovery_file)
                .expect("metadata should load")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn generates_shell_safe_daemon_tokens_with_32_bytes_of_entropy() {
        let token = generate_daemon_token();
        let second = generate_daemon_token();

        assert_eq!(token.len(), 43);
        assert_ne!(token, second);
        assert!(
            token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        );
    }

    #[test]
    fn builds_authenticated_local_request_headers() {
        let record = sample_record(LOCAL_API_VERSION);

        let headers = authenticated_headers(&record).expect("headers should build");
        let value = headers
            .get(reqwest::header::AUTHORIZATION)
            .expect("authorization header should be present")
            .to_str()
            .expect("authorization header should be text");

        assert_eq!(value, format!("Bearer {}", record.token));
    }

    #[test]
    fn classifies_missing_discovery() {
        let temp_dir = TempDir::new().expect("temp dir should be created");
        let paths = runtime_paths(temp_dir.path());
        create_runtime_dir(&paths.runtime_dir).expect("runtime dir should be created");

        let state = classify_discovery_with_probe(&paths, |_| unreachable!("no record to probe"))
            .expect("classification should succeed");

        assert_eq!(state, DiscoveryState::Missing);
    }

    #[test]
    fn classifies_live_discovery() {
        let (temp_dir, paths, record) = write_sample_discovery(LOCAL_API_VERSION);
        let _keep_temp_dir = temp_dir;

        let state =
            classify_discovery_with_probe(&paths, |_| ProbeResult::Live(PingResponse::current()))
                .expect("classification should succeed");

        assert_eq!(
            state,
            DiscoveryState::Live {
                record,
                ping: PingResponse::current()
            }
        );
    }

    #[test]
    fn classifies_auth_failure() {
        let (temp_dir, paths, record) = write_sample_discovery(LOCAL_API_VERSION);
        let _keep_temp_dir = temp_dir;

        let state = classify_discovery_with_probe(&paths, |_| ProbeResult::AuthFailure)
            .expect("classification should succeed");

        assert_eq!(state, DiscoveryState::AuthFailure { record });
    }

    #[test]
    fn classifies_api_incompatibility() {
        let (temp_dir, paths, record) = write_sample_discovery(LOCAL_API_VERSION);
        let _keep_temp_dir = temp_dir;

        let state = classify_discovery_with_probe(&paths, |_| {
            ProbeResult::Live(PingResponse {
                ok: true,
                version: "9.9.9".to_owned(),
                api_version: LOCAL_API_VERSION + 1,
            })
        })
        .expect("classification should succeed");

        assert_eq!(
            state,
            DiscoveryState::ApiIncompatible {
                record,
                daemon_version: Some("9.9.9".to_owned()),
                daemon_api_version: Some(LOCAL_API_VERSION + 1),
                cli_api_version: LOCAL_API_VERSION
            }
        );
    }

    #[test]
    fn classifies_stale_discovery_with_free_lock() {
        let (temp_dir, paths, record) = write_sample_discovery(LOCAL_API_VERSION);
        let _keep_temp_dir = temp_dir;

        let state = classify_discovery_with_probe(&paths, |_| ProbeResult::NoResponse)
            .expect("classification should succeed");

        assert_eq!(state, DiscoveryState::StaleLockFree { record });
    }

    #[test]
    fn classifies_stale_discovery_with_held_lock() {
        let (temp_dir, paths, record) = write_sample_discovery(LOCAL_API_VERSION);
        let _keep_temp_dir = temp_dir;
        let _lock = acquire_daemon_lock(&paths).expect("lock should be held");

        let state = classify_discovery_with_probe(&paths, |_| ProbeResult::NoResponse)
            .expect("classification should succeed");

        assert_eq!(state, DiscoveryState::StaleLockHeld { record });
    }

    #[test]
    fn daemon_lock_blocks_second_lock_probe() {
        let temp_dir = TempDir::new().expect("temp dir should be created");
        let paths = runtime_paths(temp_dir.path());
        create_runtime_dir(&paths.runtime_dir).expect("runtime dir should be created");

        let _lock = acquire_daemon_lock(&paths).expect("first lock should be acquired");

        assert!(!probe_lock_available(&paths).expect("lock probe should succeed"));
    }

    #[test]
    fn missing_discovery_loads_as_none() {
        let temp_dir = TempDir::new().expect("temp dir should be created");
        let paths = runtime_paths(temp_dir.path());
        create_runtime_dir(&paths.runtime_dir).expect("runtime dir should be created");

        assert_eq!(
            load_discovery_record(&paths).expect("load should succeed"),
            None
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_insecure_discovery_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = TempDir::new().expect("temp dir should be created");
        let paths = runtime_paths(temp_dir.path());
        create_runtime_dir(&paths.runtime_dir).expect("runtime dir should be created");
        let record = sample_record(LOCAL_API_VERSION);
        let json = serde_json::to_vec(&record).expect("record should serialize");
        fs::write(&paths.discovery_file, json).expect("discovery should be written");
        fs::set_permissions(&paths.discovery_file, fs::Permissions::from_mode(0o644))
            .expect("permissions should be changed");

        let error = load_discovery_record(&paths).expect_err("insecure file should fail");

        assert!(matches!(error, DiscoveryError::InsecurePath { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_discovery_file() {
        use std::os::unix::fs::symlink;

        let temp_dir = TempDir::new().expect("temp dir should be created");
        let paths = runtime_paths(temp_dir.path());
        create_runtime_dir(&paths.runtime_dir).expect("runtime dir should be created");
        let target = temp_dir.path().join("target.json");
        fs::write(&target, "{}").expect("target should be written");
        symlink(&target, &paths.discovery_file).expect("symlink should be created");

        let error = load_discovery_record(&paths).expect_err("symlink should fail");

        assert!(matches!(error, DiscoveryError::InsecurePath { .. }));
    }

    fn write_sample_discovery(api_version: u16) -> (TempDir, RuntimePaths, DiscoveryRecord) {
        let temp_dir = TempDir::new().expect("temp dir should be created");
        let paths = runtime_paths(temp_dir.path());
        create_runtime_dir(&paths.runtime_dir).expect("runtime dir should be created");
        let record = sample_record(api_version);
        write_discovery_record(&paths, &record).expect("discovery should be written");
        (temp_dir, paths, record)
    }

    fn runtime_paths(base: &std::path::Path) -> RuntimePaths {
        RuntimePaths::new(base.join("runtime"))
    }

    fn sample_record(api_version: u16) -> DiscoveryRecord {
        DiscoveryRecord {
            pid: 12345,
            addr: "127.0.0.1:49152"
                .parse::<SocketAddr>()
                .expect("addr should parse"),
            token: "local-test-token".to_owned(),
            started_at: OffsetDateTime::from_unix_timestamp(1_800_000_000)
                .expect("timestamp should be valid"),
            version: "0.1.0".to_owned(),
            api_version,
        }
    }

    #[test]
    fn discovery_file_name_matches_spec() {
        assert_eq!(DAEMON_DISCOVERY_FILE, "daemon.json");
    }

    #[test]
    fn agent_state_validates_agent_handle_grammar() {
        assert!(super::is_valid_agent_handle("0123456789ABCDEFGHJKMNPQRS"));
        assert!(!super::is_valid_agent_handle("0123456789ABCDEFGHJKMNPQR"));
        assert!(!super::is_valid_agent_handle("0123456789ABCDEFGHJKMNPQRI"));
        assert!(!super::is_valid_agent_handle("0123456789abcdefghjkmnpqrs"));
    }

    #[test]
    fn agent_state_generated_agent_handles_match_grammar() {
        let handle = super::AgentHandle::generate();

        assert!(super::is_valid_agent_handle(handle.as_str()));
    }

    #[tokio::test]
    async fn active_handle_tracks_most_recent_insert_and_clears_on_close() {
        let store = agent_store(10, 100);
        assert_eq!(store.active_handle().await, None);

        let first = super::AgentHandle::generate();
        store
            .insert_connected(first.clone(), vec!["elf".to_owned()])
            .await
            .expect("agent should insert");
        assert_eq!(store.active_handle().await, Some(first.clone()));

        let second = super::AgentHandle::generate();
        store
            .insert_connected(second.clone(), vec!["elf".to_owned()])
            .await
            .expect("agent should insert");
        assert_eq!(store.active_handle().await, Some(second.clone()));

        // Closing a non-active agent leaves the active one in place.
        store.close(&first).await.expect("close should succeed");
        assert_eq!(store.active_handle().await, Some(second.clone()));

        // Closing the active agent clears it.
        store.close(&second).await.expect("close should succeed");
        assert_eq!(store.active_handle().await, None);
    }

    #[tokio::test]
    async fn snapshot_carries_chat_channel_when_present() {
        let store = agent_store(10, 100);
        let handle = handle();
        store
            .insert_connected_with_router_channels(
                handle.clone(),
                vec!["elf".to_owned()],
                None,
                None,
                Some("@aria".to_owned()),
                Some("@research".to_owned()),
            )
            .await
            .expect("agent should insert");

        let status = store.status_snapshots().await;
        assert_eq!(status[0].channel.as_deref(), Some("@research"));

        // A router agent has no channel.
        let router_handle = super::AgentHandle::generate();
        store
            .insert_connected(router_handle.clone(), vec!["elf".to_owned()])
            .await
            .expect("agent should insert");
        let status = store.status_snapshots().await;
        let router_status = status
            .iter()
            .find(|status| status.agent_handle == router_handle.as_str())
            .expect("router agent snapshot exists");
        assert_eq!(router_status.channel, None);
    }

    #[tokio::test]
    async fn agent_state_queue_delivers_fifo_and_tracks_bytes() {
        let store = agent_store(10, 100);
        let handle = handle();
        store
            .insert_connected(handle.clone(), vec!["elf".to_owned()])
            .await
            .expect("agent should insert");

        store
            .enqueue_inbound(&handle, "one".to_owned())
            .await
            .expect("enqueue should succeed");
        store
            .enqueue_inbound(&handle, "two-two".to_owned())
            .await
            .expect("enqueue should succeed");

        let status = store.status_snapshots().await;
        assert_eq!(status[0].queued_messages, 2);
        assert_eq!(status[0].queued_bytes, 10);

        assert_eq!(
            store
                .recv(&handle, None)
                .await
                .expect("recv should succeed"),
            "one"
        );
        let status = store.status_snapshots().await;
        assert_eq!(status[0].queued_messages, 1);
        assert_eq!(status[0].queued_bytes, 7);
        assert_eq!(
            store
                .recv(&handle, None)
                .await
                .expect("recv should succeed"),
            "two-two"
        );
    }

    #[tokio::test]
    async fn agent_state_queue_overflow_marks_handle_unhealthy() {
        let store = agent_store(1, 100);
        let handle = handle();
        store
            .insert_connected(handle.clone(), vec!["elf".to_owned()])
            .await
            .expect("agent should insert");
        store
            .enqueue_inbound(&handle, "one".to_owned())
            .await
            .expect("first enqueue should succeed");

        let error = store
            .enqueue_inbound(&handle, "two".to_owned())
            .await
            .expect_err("overflow should fail");

        assert_eq!(error, super::AgentError::QueueOverflow);
        let status = store.status_snapshots().await;
        assert_eq!(status[0].state, super::AgentState::Unhealthy);
        assert_eq!(
            status[0].unhealthy_reason.as_deref(),
            Some("queue_overflow")
        );
        assert_eq!(
            store
                .recv(&handle, Some(std::time::Duration::from_millis(1)))
                .await
                .expect_err("unhealthy recv should fail"),
            super::AgentError::Unhealthy {
                reason: "queue_overflow".to_owned(),
                detail: None,
            }
        );
    }

    /// SPEC-026 CON-003 / TEST-004 (unit half) — a handle whose socket is down
    /// is `reconnecting`, and `reconnecting` is **healthy for admission**: a
    /// `recv` keeps waiting and a send still reaches the transport loop. This is
    /// the load-bearing half of the issue-#25 fix at the store level — the old
    /// behaviour marked the handle `unhealthy`, which is terminal and is what
    /// stranded the agent.
    #[tokio::test]
    async fn reconnecting_is_healthy_for_admission_and_reports_its_progress() {
        let store = agent_store(10, 100);
        let handle = handle();
        store
            .insert_connected(handle.clone(), vec!["elf".to_owned()])
            .await
            .expect("agent should insert");

        store
            .mark_reconnecting(&handle, 3, Some("hub closed the socket".to_owned()))
            .await
            .expect("mark_reconnecting should succeed");

        let status = store.status_snapshots().await;
        assert_eq!(status[0].state, super::AgentState::Reconnecting);
        assert_eq!(status[0].state.as_str(), "reconnecting");
        assert_eq!(status[0].reconnect_attempts, 3);
        assert_eq!(
            status[0].reconnect_detail.as_deref(),
            Some("hub closed the socket")
        );
        // Negative-output: the terminal fields keep their terminal meaning. A
        // reconnecting agent is NOT reporting an unhealthy reason.
        assert_eq!(status[0].unhealthy_reason, None);
        assert_eq!(status[0].unhealthy_detail, None);

        // A recv against a reconnecting handle waits (and times out) rather than
        // erroring `Unhealthy` — the gap is a pause, not a death.
        assert_eq!(
            store
                .recv(&handle, Some(std::time::Duration::from_millis(1)))
                .await
                .expect_err("an empty queue still times out"),
            super::AgentError::RecvTimeout,
        );

        // Recovery clears both the state and the progress fields.
        store
            .mark_connected(&handle)
            .await
            .expect("mark_connected should succeed");
        let status = store.status_snapshots().await;
        assert_eq!(status[0].state, super::AgentState::Connected);
        assert_eq!(status[0].reconnect_attempts, 0);
        assert_eq!(status[0].reconnect_detail, None);
    }

    /// SPEC-026 CON-003 (negative-output) — marking a handle reconnecting must
    /// not close its connection or drop a pending meta waiter, the two things
    /// `mark_unhealthy` deliberately does. A reconnect that tore down the
    /// close-signal would make `hark close` unable to reach the transport loop.
    #[tokio::test]
    async fn reconnecting_does_not_tear_the_connection_down() {
        let store = agent_store(10, 100);
        let handle = handle();
        let (close_tx, mut close_rx) = tokio::sync::oneshot::channel();
        store
            .insert_connected_with_close_signal(
                handle.clone(),
                vec!["elf".to_owned()],
                Some(close_tx),
            )
            .await
            .expect("agent should insert");

        store
            .mark_reconnecting(&handle, 1, Some("io error".to_owned()))
            .await
            .expect("mark_reconnecting should succeed");

        assert!(
            matches!(close_rx.try_recv(), Err(tokio::sync::oneshot::error::TryRecvError::Empty)),
            "the close signal must stay armed across a reconnect"
        );

        // And the transition is still terminal-capable: mark_unhealthy from the
        // reconnecting state does fire it.
        store
            .mark_unhealthy(&handle, "hub_rejected", Some("forbidden-room".to_owned()))
            .await
            .expect("mark_unhealthy should succeed");
        assert!(
            close_rx.try_recv().is_ok(),
            "a terminal transition still closes the connection"
        );
    }

    /// A *retryable* outbound reject (MLS membership not yet established) must
    /// surface as [`AgentError::NotReady`] and leave the handle healthy — a
    /// membership race must not strand the handle. A *fatal* reject still
    /// marks it unhealthy. This is the SPEC-013 REQ-023 regression: `emit`
    /// racing ahead of the Welcome used to poison the handle.
    #[tokio::test]
    async fn retryable_outbound_reject_keeps_handle_healthy() {
        let store = agent_store(10, 100);

        // A fake transport loop: reply to the first frame with a retryable
        // reject, the second with a fatal one.
        let (tx, mut rx) = tokio::sync::mpsc::channel::<super::OutboundFrame>(4);
        tokio::spawn(async move {
            if let Some(frame) = rx.recv().await {
                let _ = frame
                    .result_tx
                    .send(Err(super::OutboundReject::retryable("not yet a member")));
            }
            if let Some(frame) = rx.recv().await {
                let _ = frame
                    .result_tx
                    .send(Err(super::OutboundReject::fatal("socket died")));
            }
        });

        let handle = handle();
        store
            .insert_connected_with_router_channels(
                handle.clone(),
                vec!["elf".to_owned()],
                None,
                Some(super::AgentSendChannel::new(tx)),
                Some("@aria".to_owned()),
                Some("@research".to_owned()),
            )
            .await
            .expect("agent should insert");

        // Retryable: NotReady, handle stays Connected.
        let error = store
            .send_outbound(&handle, "(deliver @research)".to_owned())
            .await
            .expect_err("retryable reject should error");
        assert_eq!(
            error,
            super::AgentError::NotReady {
                detail: Some("not yet a member".to_owned()),
            }
        );
        let status = store.status_snapshots().await;
        assert_eq!(
            status[0].state,
            super::AgentState::Connected,
            "a transient not-ready reject must not poison the handle"
        );

        // Fatal: Unhealthy, handle poisoned as before.
        let error = store
            .send_outbound(&handle, "(deliver @research)".to_owned())
            .await
            .expect_err("fatal reject should error");
        assert!(matches!(
            error,
            super::AgentError::Unhealthy { .. }
        ));
        let status = store.status_snapshots().await;
        assert_eq!(status[0].state, super::AgentState::Unhealthy);
    }

    #[tokio::test]
    async fn agent_state_queue_overflow_accounts_bytes() {
        let store = agent_store(10, 3);
        let handle = handle();
        store
            .insert_connected(handle.clone(), vec!["elf".to_owned()])
            .await
            .expect("agent should insert");

        let error = store
            .enqueue_inbound(&handle, "four".to_owned())
            .await
            .expect_err("byte overflow should fail");

        assert_eq!(error, super::AgentError::QueueOverflow);
    }

    #[tokio::test]
    async fn agent_state_close_removes_connected_and_unhealthy_handles() {
        let store = agent_store(10, 100);
        let handle = handle();
        store
            .insert_connected(handle.clone(), vec!["elf".to_owned()])
            .await
            .expect("agent should insert");
        store
            .mark_unhealthy(&handle, "router_closed", None)
            .await
            .expect("mark unhealthy should succeed");

        store.close(&handle).await.expect("close should succeed");

        assert_eq!(
            store
                .close(&handle)
                .await
                .expect_err("second close should fail"),
            super::AgentError::UnknownHandle
        );
    }

    #[tokio::test]
    async fn agent_state_allows_only_one_blocking_recv_waiter_per_handle() {
        let store = agent_store(10, 100);
        let handle = handle();
        store
            .insert_connected(handle.clone(), vec!["elf".to_owned()])
            .await
            .expect("agent should insert");
        let waiter_store = store.clone();
        let waiter_handle = handle.clone();
        let waiter = tokio::spawn(async move {
            waiter_store
                .recv(&waiter_handle, Some(std::time::Duration::from_secs(5)))
                .await
        });

        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        assert_eq!(
            store
                .recv(&handle, Some(std::time::Duration::from_millis(1)))
                .await
                .expect_err("second waiter should fail"),
            super::AgentError::RecvAlreadyWaiting
        );
        store
            .enqueue_inbound(&handle, "work".to_owned())
            .await
            .expect("enqueue should wake waiter");
        assert_eq!(
            waiter
                .await
                .expect("waiter task should not panic")
                .expect("waiter should receive"),
            "work"
        );
    }

    #[tokio::test]
    async fn agent_state_recv_timeout_clears_waiter() {
        let store = agent_store(10, 100);
        let handle = handle();
        store
            .insert_connected(handle.clone(), vec!["elf".to_owned()])
            .await
            .expect("agent should insert");

        assert_eq!(
            store
                .recv(&handle, Some(std::time::Duration::from_millis(1)))
                .await
                .expect_err("recv should time out"),
            super::AgentError::RecvTimeout
        );

        store
            .enqueue_inbound(&handle, "later".to_owned())
            .await
            .expect("enqueue should succeed");
        assert_eq!(
            store
                .recv(&handle, None)
                .await
                .expect("recv should succeed"),
            "later"
        );
    }

    #[tokio::test]
    async fn agent_state_dropped_recv_clears_waiter() {
        let store = agent_store(10, 100);
        let handle = handle();
        store
            .insert_connected(handle.clone(), vec!["elf".to_owned()])
            .await
            .expect("agent should insert");
        let waiter_store = store.clone();
        let waiter_handle = handle.clone();
        let waiter = tokio::spawn(async move { waiter_store.recv(&waiter_handle, None).await });

        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        waiter.abort();
        let _ = waiter.await.expect_err("waiter task should be aborted");

        for _ in 0..20 {
            match store
                .recv(&handle, Some(std::time::Duration::from_millis(1)))
                .await
            {
                Err(super::AgentError::RecvAlreadyWaiting) => {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
                Err(super::AgentError::RecvTimeout) => break,
                other => panic!("expected cleared waiter to allow a timeout, got {other:?}"),
            }
        }

        store
            .enqueue_inbound(&handle, "later".to_owned())
            .await
            .expect("enqueue should succeed");
        assert_eq!(
            store
                .recv(&handle, None)
                .await
                .expect("recv should succeed"),
            "later"
        );
    }

    #[tokio::test]
    async fn agent_state_status_snapshots_include_agent_metadata() {
        let store = agent_store(10, 100);
        let handle = handle();

        let snapshot = store
            .insert_connected(
                handle.clone(),
                vec!["elf".to_owned(), "arena-v1".to_owned()],
            )
            .await
            .expect("agent should insert");

        assert_eq!(snapshot.agent_handle, handle.as_str());
        assert_eq!(
            snapshot.router_agent_id,
            format!("local-agent-{}", handle.as_str())
        );
        assert_eq!(snapshot.dialects, ["elf", "arena-v1"]);
        assert_eq!(snapshot.state, super::AgentState::Connected);
    }

    #[tokio::test]
    async fn agent_state_validates_agent_advertisements() {
        let store = agent_store(10, 100);
        let handle = handle();

        // SPEC-016 HP-2: an empty advertisement is "advertise nothing" —
        // a chat agent may join a channel without speaking any dialect.
        let snapshot = store
            .insert_connected(handle.clone(), vec![])
            .await
            .expect("empty advertisement should be allowed");
        assert!(snapshot.dialects.is_empty());
        store.close(&handle).await.expect("close should succeed");

        let handle = super::AgentHandle::generate();
        assert_eq!(
            store
                .insert_connected(handle, vec!["elf".to_owned(), "elf".to_owned()])
                .await
                .expect_err("duplicate dialect should fail"),
            super::AgentError::DuplicateDialect
        );
    }

    #[tokio::test]
    async fn try_route_meta_reply_does_not_steal_unrelated_push() {
        // A `Reply`-expecting waiter (publish/list) must not be satisfied
        // by an unsolicited subscription push. The push should fall through
        // to the inbound queue so the awaited reply arrives correctly.
        use super::{MetaReplyDelivery, MetaReplyExpectation, PendingMetaReply};
        let store = agent_store(8, 4096);
        let handle = handle();
        store
            .insert_connected(handle.clone(), vec!["elf".to_owned()])
            .await
            .expect("insert");
        let (tx, rx) = tokio::sync::oneshot::channel();
        {
            let mut inner = store.inner.lock().await;
            let entry = inner.agents.get_mut(&handle).expect("entry");
            entry.pending_meta_reply = Some(PendingMetaReply {
                expectation: MetaReplyExpectation::Reply,
                sender: tx,
            });
        }

        let push = MetaReplyDelivery::PushInstalled {
            name: "arena-v1".to_owned(),
            define_form: "(define arena-v1 ...)".to_owned(),
            digest: "deadbeef".to_owned(),
            frame: "(meta (teach @local (define arena-v1 ...)))".to_owned(),
        };
        let leftover = store
            .try_route_meta_reply(&handle, push)
            .await
            .expect("push must NOT be consumed by a Reply waiter");
        assert!(leftover.starts_with("(meta (teach"));

        // Waiter remains armed; an actual reply still routes to it.
        let reply = MetaReplyDelivery::Reply("(reply @x \"ok\" :thread \"t-1\")".to_owned());
        assert!(store.try_route_meta_reply(&handle, reply).await.is_none());
        let delivered = rx.await.expect("waiter should receive reply");
        assert!(matches!(delivered, MetaReplyDelivery::Reply(_)));
    }

    #[tokio::test]
    async fn try_route_meta_reply_filters_push_by_name() {
        // A query for `arena-v1` must not consume a push for `other-dialect`.
        use super::{MetaReplyDelivery, MetaReplyExpectation, PendingMetaReply};
        let store = agent_store(8, 4096);
        let handle = handle();
        store
            .insert_connected(handle.clone(), vec!["elf".to_owned()])
            .await
            .expect("insert");
        let (tx, _rx) = tokio::sync::oneshot::channel();
        {
            let mut inner = store.inner.lock().await;
            let entry = inner.agents.get_mut(&handle).expect("entry");
            entry.pending_meta_reply = Some(PendingMetaReply {
                expectation: MetaReplyExpectation::ReplyOrPushNamed("arena-v1".to_owned()),
                sender: tx,
            });
        }

        let unrelated = MetaReplyDelivery::PushInstalled {
            name: "other-dialect".to_owned(),
            define_form: "(define other-dialect ...)".to_owned(),
            digest: "abc".to_owned(),
            frame: "(meta (teach @local (define other-dialect ...)))".to_owned(),
        };
        assert!(
            store
                .try_route_meta_reply(&handle, unrelated)
                .await
                .is_some(),
            "mismatched push name must NOT be consumed by the query waiter"
        );
    }

    #[tokio::test]
    async fn queue_overflow_clears_pending_meta_waiter() {
        // The inbound-queue overflow path calls `AgentEntry::mark_unhealthy`
        // directly. With the meta-reply correlation in place, unrelated
        // subscription pushes can fall through to the queue, so this path
        // is now reachable while a publish/list/query waiter is armed —
        // the waiter must observe the close immediately rather than
        // waiting META_REPLY_TIMEOUT.
        use super::{MetaReplyExpectation, PendingMetaReply};
        let store = agent_store(1, 64);
        let handle = handle();
        store
            .insert_connected(handle.clone(), vec!["elf".to_owned()])
            .await
            .expect("insert");
        let (tx, rx) = tokio::sync::oneshot::channel();
        {
            let mut inner = store.inner.lock().await;
            let entry = inner.agents.get_mut(&handle).expect("entry");
            entry.pending_meta_reply = Some(PendingMetaReply {
                expectation: MetaReplyExpectation::Reply,
                sender: tx,
            });
        }

        // First enqueue fits; second blows the per-handle cap and triggers
        // `mark_unhealthy("queue_overflow", _)` on the entry directly.
        store
            .enqueue_inbound(&handle, "first".to_owned())
            .await
            .expect("first enqueue");
        let _ = store.enqueue_inbound(&handle, "second".to_owned()).await;

        rx.await
            .expect_err("waiter sender should drop on queue-overflow unhealthy path");
    }

    #[tokio::test]
    async fn mark_unhealthy_clears_pending_meta_waiter() {
        use super::{MetaReplyExpectation, PendingMetaReply};
        let store = agent_store(8, 4096);
        let handle = handle();
        store
            .insert_connected(handle.clone(), vec!["elf".to_owned()])
            .await
            .expect("insert");
        let (tx, rx) = tokio::sync::oneshot::channel();
        {
            let mut inner = store.inner.lock().await;
            let entry = inner.agents.get_mut(&handle).expect("entry");
            entry.pending_meta_reply = Some(PendingMetaReply {
                expectation: MetaReplyExpectation::Reply,
                sender: tx,
            });
        }

        store
            .mark_unhealthy(&handle, "router_closed", Some("test".to_owned()))
            .await
            .expect("mark_unhealthy");

        // The pending sender must have been dropped so the awaiting caller
        // observes a closed channel immediately, not META_REPLY_TIMEOUT.
        rx.await
            .expect_err("waiter sender should be dropped when handle goes unhealthy");
    }

    #[tokio::test]
    async fn per_handle_store_appends_and_looks_up_messages() {
        use cbcl_core::{
            message::{CorePerformative, Message, Performative},
            sexpr::{Atom, SExpr},
            store::{ContentHash, ThreadId},
        };

        let store = agent_store(10, 1024);
        let handle = handle();
        store
            .insert_connected(handle.clone(), vec!["elf".to_owned()])
            .await
            .expect("agent should insert");

        let message = Message::Simple {
            performative: Performative::Core(CorePerformative::Tell),
            recipient: None,
            content: SExpr::Atom(Atom::Str("hello".into())),
            params: Vec::new(),
            thread: Some("rcp-1".into()),
            sender: None,
            caused_by: Some(cbcl_core::message::CausedBy::Begin),
        };
        let hash = ContentHash("hash-a".into());
        let thread = ThreadId("rcp-1".into());

        let inserted = store
            .append_message(&handle, hash.clone(), thread.clone(), message.clone())
            .await
            .expect("append should succeed");
        assert!(inserted, "first append must report new insertion");

        // Second append of same hash is a dedup.
        let dup = store
            .append_message(&handle, hash.clone(), thread, message.clone())
            .await
            .expect("append should succeed");
        assert!(!dup, "duplicate hash must be deduplicated");

        let found = store
            .lookup_message(&handle, &hash)
            .await
            .expect("lookup should succeed");
        assert_eq!(found.as_ref(), Some(&message));

        // Unknown handle path.
        let missing = super::AgentHandle::new("ZZZZZZZZZZZZZZZZZZZZZZZZZZ").unwrap();
        let err = store
            .append_message(&missing, hash, ThreadId("rcp-1".into()), message)
            .await
            .expect_err("unknown handle must error");
        assert!(matches!(err, super::AgentError::UnknownHandle));
    }

    fn agent_store(max_messages: usize, max_bytes: usize) -> super::AgentStore {
        super::AgentStore::new(super::AgentStoreConfig {
            agent_id_prefix: "local-agent".to_owned(),
            max_messages_per_handle: max_messages,
            max_bytes_per_handle: max_bytes,
        })
    }

    fn handle() -> super::AgentHandle {
        super::AgentHandle::new("0123456789ABCDEFGHJKMNPQRS").expect("handle should be valid")
    }
}
