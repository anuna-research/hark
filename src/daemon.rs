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
use tokio::sync::{Mutex, Notify};

use crate::{
    config::{validate_capability_name, validate_dialect_id},
    constants::LOCAL_API_VERSION,
    local_api::PingResponse,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AgentState {
    Connected,
    Unhealthy,
}

impl AgentState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Connected => "connected",
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
    pub capabilities: Vec<String>,
    pub dialects: Vec<String>,
    pub state: AgentState,
    pub queued_messages: usize,
    pub queued_bytes: usize,
    pub unhealthy_reason: Option<String>,
    pub unhealthy_detail: Option<String>,
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
    #[error("a receive call is already waiting for this handle")]
    RecvAlreadyWaiting,
    #[error("receive timed out")]
    RecvTimeout,
    #[error("queue overflow")]
    QueueOverflow,
    #[error("missing capability")]
    MissingCapability,
    #[error("duplicate capability")]
    DuplicateCapability,
    #[error("duplicate dialect")]
    DuplicateDialect,
    #[error("invalid capability: {0}")]
    InvalidCapability(String),
    #[error("invalid dialect: {0}")]
    InvalidDialect(String),
}

#[derive(Debug)]
struct AgentRegistry {
    config: AgentStoreConfig,
    agents: HashMap<AgentHandle, AgentEntry>,
}

#[derive(Debug)]
struct AgentEntry {
    router_agent_id: String,
    capabilities: Vec<String>,
    dialects: Vec<String>,
    state: AgentState,
    unhealthy_reason: Option<String>,
    unhealthy_detail: Option<String>,
    queue: VecDeque<QueuedMessage>,
    queued_bytes: usize,
    recv_waiting: bool,
    notify: Arc<Notify>,
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
            })),
        }
    }

    pub async fn insert_connected(
        &self,
        handle: AgentHandle,
        capabilities: Vec<String>,
        dialects: Vec<String>,
    ) -> Result<AgentStatusSnapshot, AgentError> {
        validate_agent_advertisement(&capabilities, &dialects)?;
        let mut inner = self.inner.lock().await;
        let router_agent_id = format!("{}-{}", inner.config.agent_id_prefix, handle.as_str());
        let entry = AgentEntry {
            router_agent_id,
            capabilities,
            dialects,
            state: AgentState::Connected,
            unhealthy_reason: None,
            unhealthy_detail: None,
            queue: VecDeque::new(),
            queued_bytes: 0,
            recv_waiting: false,
            notify: Arc::new(Notify::new()),
        };
        inner.agents.insert(handle.clone(), entry);
        Ok(inner
            .agents
            .get(&handle)
            .expect("agent was just inserted")
            .snapshot(&handle))
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
        let notify = {
            let mut inner = self.inner.lock().await;
            let entry = inner
                .agents
                .get_mut(handle)
                .ok_or(AgentError::UnknownHandle)?;
            entry.ensure_healthy()?;
            if let Some(message) = entry.pop_message() {
                return Ok(message);
            }
            if entry.recv_waiting {
                return Err(AgentError::RecvAlreadyWaiting);
            }
            entry.recv_waiting = true;
            Arc::clone(&entry.notify)
        };

        let wait = async {
            loop {
                notify.notified().await;
                let mut inner = self.inner.lock().await;
                let Some(entry) = inner.agents.get_mut(handle) else {
                    return Err(AgentError::UnknownHandle);
                };
                if let Err(error) = entry.ensure_healthy() {
                    entry.recv_waiting = false;
                    return Err(error);
                }
                if let Some(message) = entry.pop_message() {
                    entry.recv_waiting = false;
                    return Ok(message);
                }
            }
        };

        match timeout {
            Some(timeout) => match tokio::time::timeout(timeout, wait).await {
                Ok(result) => result,
                Err(_) => {
                    self.clear_waiter(handle).await;
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
        entry.notify.notify_waiters();
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

    async fn clear_waiter(&self, handle: &AgentHandle) {
        let mut inner = self.inner.lock().await;
        if let Some(entry) = inner.agents.get_mut(handle) {
            entry.recv_waiting = false;
        }
    }
}

impl AgentEntry {
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
    }

    fn snapshot(&self, handle: &AgentHandle) -> AgentStatusSnapshot {
        AgentStatusSnapshot {
            agent_handle: handle.as_str().to_owned(),
            router_agent_id: self.router_agent_id.clone(),
            capabilities: self.capabilities.clone(),
            dialects: self.dialects.clone(),
            state: self.state,
            queued_messages: self.queue.len(),
            queued_bytes: self.queued_bytes,
            unhealthy_reason: self.unhealthy_reason.clone(),
            unhealthy_detail: self.unhealthy_detail.clone(),
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

fn validate_agent_advertisement(
    capabilities: &[String],
    dialects: &[String],
) -> Result<(), AgentError> {
    if capabilities.is_empty() {
        return Err(AgentError::MissingCapability);
    }

    let mut seen = std::collections::HashSet::new();
    for capability in capabilities {
        validate_capability_name(capability)
            .map_err(|error| AgentError::InvalidCapability(error.to_string()))?;
        if !seen.insert(capability) {
            return Err(AgentError::DuplicateCapability);
        }
    }

    seen.clear();
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
    async fn agent_state_queue_delivers_fifo_and_tracks_bytes() {
        let store = agent_store(10, 100);
        let handle = handle();
        store
            .insert_connected(handle.clone(), vec!["code:edit".to_owned()], vec![])
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
            .insert_connected(handle.clone(), vec!["code:edit".to_owned()], vec![])
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

    #[tokio::test]
    async fn agent_state_queue_overflow_accounts_bytes() {
        let store = agent_store(10, 3);
        let handle = handle();
        store
            .insert_connected(handle.clone(), vec!["code:edit".to_owned()], vec![])
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
            .insert_connected(handle.clone(), vec!["code:edit".to_owned()], vec![])
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
            .insert_connected(handle.clone(), vec!["code:edit".to_owned()], vec![])
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
            .insert_connected(handle.clone(), vec!["code:edit".to_owned()], vec![])
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
    async fn agent_state_status_snapshots_include_agent_metadata() {
        let store = agent_store(10, 100);
        let handle = handle();

        let snapshot = store
            .insert_connected(
                handle.clone(),
                vec!["code:edit".to_owned(), "code:test".to_owned()],
                vec!["elf".to_owned()],
            )
            .await
            .expect("agent should insert");

        assert_eq!(snapshot.agent_handle, handle.as_str());
        assert_eq!(
            snapshot.router_agent_id,
            format!("local-agent-{}", handle.as_str())
        );
        assert_eq!(snapshot.capabilities, ["code:edit", "code:test"]);
        assert_eq!(snapshot.dialects, ["elf"]);
        assert_eq!(snapshot.state, super::AgentState::Connected);
    }

    #[tokio::test]
    async fn agent_state_validates_agent_advertisements() {
        let store = agent_store(10, 100);
        let handle = handle();

        assert_eq!(
            store
                .insert_connected(handle.clone(), vec![], vec![])
                .await
                .expect_err("missing capability should fail"),
            super::AgentError::MissingCapability
        );
        assert_eq!(
            store
                .insert_connected(
                    handle.clone(),
                    vec!["code:edit".to_owned(), "code:edit".to_owned()],
                    vec![],
                )
                .await
                .expect_err("duplicate capability should fail"),
            super::AgentError::DuplicateCapability
        );
        assert_eq!(
            store
                .insert_connected(
                    handle,
                    vec!["code:edit".to_owned()],
                    vec!["elf".to_owned(), "elf".to_owned()],
                )
                .await
                .expect_err("duplicate dialect should fail"),
            super::AgentError::DuplicateDialect
        );
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
