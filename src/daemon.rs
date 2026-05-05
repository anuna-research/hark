use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use directories::BaseDirs;
use fs2::FileExt;
use rand::TryRngCore;
use rand::rngs::OsRng;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{constants::LOCAL_API_VERSION, local_api::PingResponse};

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum AgentState {
    Connected,
    Unhealthy,
}

pub const DAEMON_LOCK_FILE: &str = "daemon.lock";
pub const DAEMON_DISCOVERY_FILE: &str = "daemon.json";
const DAEMON_TOKEN_BYTES: usize = 32;

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
}
