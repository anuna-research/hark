use std::{env, fmt, net::SocketAddr, path::PathBuf};

use config::{Config, File};
use directories::BaseDirs;
use serde::Deserialize;
use url::Url;

use crate::constants::{
    COMMAND_NAME, DEFAULT_AGENT_ID_PREFIX, DEFAULT_DAEMON_BIND, DEFAULT_MAX_BYTES_PER_HANDLE,
    DEFAULT_MAX_MESSAGES_PER_HANDLE, DEFAULT_OVERFLOW_POLICY,
};

pub const SAMPLE_CONFIG: &str = r#"# ws_url's PATH selects the transport: /chat/v1 -> cbcl-chat, anything else -> router.
[router]
ws_url = "wss://cbcl-lfe.anuna.io/agent/v1"
auth_token = "shr_prod-agent.REPLACE_ME"

# Used only when ws_url points at a chat hub (path /chat/v1). The wire handle is
# per process: `hark init --handle @aria --channel @general` (each handle is
# enrolled separately with the hub and signed by its own key under identity_dir).
[chat]
channel = "@general"
# identity_dir defaults to <config-dir>/chat-keys; one <handle>.key per agent.

[agent]
agent_id_prefix = "local-agent"

[daemon]
bind = "127.0.0.1:0"
max_messages_per_handle = 1000
max_bytes_per_handle = 67108864
overflow_policy = "reject_new_and_close"
"#;

/// Default chat channel when neither `--channel` nor `[chat].channel` is set.
pub const DEFAULT_CHAT_CHANNEL: &str = "@general";

/// Which upstream transport a connection uses, decided by the `ws_url` path.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Transport {
    Router,
    Chat,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
#[serde(default)]
pub struct AppConfig {
    pub router: RouterConfig,
    pub chat: ChatConfig,
    pub agent: AgentConfig,
    pub daemon: DaemonConfig,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Default)]
#[serde(default)]
pub struct RouterConfig {
    pub ws_url: Option<String>,
    pub auth_token: Option<String>,
}

/// Chat-transport-only knobs. The hub URL is shared with `[router]` (the
/// `ws_url` path decides router vs chat); these are the extras the chat
/// transport needs that the router does not: a default channel, and where
/// per-handle signing keys live.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Default)]
#[serde(default)]
pub struct ChatConfig {
    /// Default channel (`@name`) joined when `init` omits `--channel`.
    pub channel: Option<String>,
    /// Directory holding one Ed25519 seed per wire handle (`<dir>/<handle>.key`).
    /// Each agent process gets its own handle and its own key here.
    pub identity_dir: Option<String>,
    /// Δ: how long to collect claims before electing an answerer, in
    /// milliseconds (SPEC-003 NFR-001). Defaults to 400 ms.
    pub claim_window_ms: Option<u64>,
    /// T: per-rank liveness timeout before a fallback agent takes over, in
    /// milliseconds (SPEC-003 REQ-007/NFR-002). Defaults to 2000 ms.
    pub liveness_timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
#[serde(default)]
pub struct AgentConfig {
    pub agent_id_prefix: String,
    /// Default for `CreateAgentRequest.auto_install_advertised` when the
    /// caller does not specify. When `true`, `init` issues a meta query
    /// per advertised dialect after the hello so R5 can enforce that
    /// dialect's shape and protocol from the very first message. Set to
    /// `false` for tests or for mock-router environments where meta-query
    /// round-trips are not supported.
    pub auto_install_advertised: bool,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
#[serde(default)]
pub struct DaemonConfig {
    pub bind: String,
    pub max_messages_per_handle: usize,
    pub max_bytes_per_handle: usize,
    pub overflow_policy: String,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ValidatedRouterConfig {
    pub ws_url: Url,
    pub auth_token: String,
}

/// A validated chat-transport configuration: the hub URL plus the chat-only
/// extras with defaults applied.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ValidatedChatConfig {
    pub ws_url: Url,
    pub channel: String,
    pub identity_dir: PathBuf,
    /// Δ — the claim-collection window (SPEC-003 NFR-001).
    pub claim_window: std::time::Duration,
    /// T — the per-rank liveness timeout (SPEC-003 REQ-007).
    pub liveness_timeout: std::time::Duration,
}

/// Default Δ claim window (SPEC-003 NFR-001: ≤ 750 ms p95 for N ≤ 8 on LAN).
pub const DEFAULT_CLAIM_WINDOW_MS: u64 = 400;
/// Default T liveness timeout before a fallback agent answers.
pub const DEFAULT_LIVENESS_TIMEOUT_MS: u64 = 2000;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to load configuration: {0}")]
    Load(#[from] config::ConfigError),
    #[error("environment variable {var} is invalid: {reason}")]
    InvalidEnv { var: &'static str, reason: String },
    #[error("{field} is invalid: {reason}")]
    InvalidValue { field: &'static str, reason: String },
    #[error("missing router WebSocket URL")]
    MissingRouterWsUrl,
    #[error("invalid router WebSocket URL: {0}")]
    InvalidRouterWsUrl(String),
    #[error("missing router authentication token")]
    MissingRouterAuthToken,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            router: RouterConfig::default(),
            chat: ChatConfig::default(),
            agent: AgentConfig {
                agent_id_prefix: DEFAULT_AGENT_ID_PREFIX.to_owned(),
                auto_install_advertised: DEFAULT_AUTO_INSTALL_ADVERTISED,
            },
            daemon: DaemonConfig {
                bind: DEFAULT_DAEMON_BIND.to_owned(),
                max_messages_per_handle: DEFAULT_MAX_MESSAGES_PER_HANDLE,
                max_bytes_per_handle: DEFAULT_MAX_BYTES_PER_HANDLE,
                overflow_policy: DEFAULT_OVERFLOW_POLICY.to_owned(),
            },
        }
    }
}

const DEFAULT_AUTO_INSTALL_ADVERTISED: bool = true;

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            agent_id_prefix: DEFAULT_AGENT_ID_PREFIX.to_owned(),
            auto_install_advertised: DEFAULT_AUTO_INSTALL_ADVERTISED,
        }
    }
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            bind: DEFAULT_DAEMON_BIND.to_owned(),
            max_messages_per_handle: DEFAULT_MAX_MESSAGES_PER_HANDLE,
            max_bytes_per_handle: DEFAULT_MAX_BYTES_PER_HANDLE,
            overflow_policy: DEFAULT_OVERFLOW_POLICY.to_owned(),
        }
    }
}

impl fmt::Debug for RouterConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RouterConfig")
            .field("ws_url", &self.ws_url)
            .field(
                "auth_token",
                &self.auth_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl fmt::Debug for ValidatedRouterConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedRouterConfig")
            .field("ws_url", &self.ws_url)
            .field("auth_token", &"<redacted>")
            .finish()
    }
}

impl AppConfig {
    pub fn load() -> Result<Self, ConfigError> {
        Self::load_from(default_config_file())
    }

    pub fn load_from(config_file: Option<PathBuf>) -> Result<Self, ConfigError> {
        let mut config = load_file_backed_config(config_file)?;
        apply_environment_overrides(&mut config)?;
        Ok(config)
    }

    pub fn validate_daemon_runtime(&self) -> Result<(), ConfigError> {
        validate_agent_id_prefix(&self.agent.agent_id_prefix)?;
        validate_daemon_bind(&self.daemon.bind)?;
        validate_positive(
            "daemon.max_messages_per_handle",
            self.daemon.max_messages_per_handle,
        )?;
        validate_positive(
            "daemon.max_bytes_per_handle",
            self.daemon.max_bytes_per_handle,
        )?;

        if self.daemon.overflow_policy != DEFAULT_OVERFLOW_POLICY {
            return Err(ConfigError::InvalidValue {
                field: "daemon.overflow_policy",
                reason: format!("only `{DEFAULT_OVERFLOW_POLICY}` is supported"),
            });
        }

        Ok(())
    }

    /// Parse and scheme-check the configured hub WebSocket URL. Shared by both
    /// transports; the URL's *path* is what then selects router vs chat.
    pub fn validate_ws_url(&self) -> Result<Url, ConfigError> {
        let ws_url = self
            .router
            .ws_url
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .ok_or(ConfigError::MissingRouterWsUrl)?;
        let ws_url = Url::parse(ws_url)
            .map_err(|error| ConfigError::InvalidRouterWsUrl(error.to_string()))?;
        if !matches!(ws_url.scheme(), "ws" | "wss") {
            return Err(ConfigError::InvalidRouterWsUrl(
                "URL scheme must be ws or wss".to_owned(),
            ));
        }
        Ok(ws_url)
    }

    /// Select the transport from the configured hub URL: path `/chat/v1` is the
    /// cbcl-chat transport, anything else is the router.
    pub fn transport(&self) -> Result<Transport, ConfigError> {
        let ws_url = self.validate_ws_url()?;
        Ok(if ws_url.path() == crate::chat::CHAT_WS_PATH {
            Transport::Chat
        } else {
            Transport::Router
        })
    }

    pub fn validate_router(&self) -> Result<ValidatedRouterConfig, ConfigError> {
        let ws_url = self.validate_ws_url()?;
        // SPEC-012 REQ-009: the router no longer uses a bearer token — identity is
        // established per frame by Ed25519 signature (see signed_transport). A
        // legacy `auth_token` in the config is accepted but ignored.
        let auth_token = self.router.auth_token.as_deref().unwrap_or("").to_owned();

        Ok(ValidatedRouterConfig { ws_url, auth_token })
    }

    /// Validate the chat transport: the shared hub URL, plus the chat-only
    /// extras with defaults applied (channel → `@general`, identity_dir →
    /// `<config-dir>/chat-keys`). Unlike the router, chat needs no auth token —
    /// it authenticates per frame by Ed25519 signature.
    pub fn validate_chat(&self) -> Result<ValidatedChatConfig, ConfigError> {
        let ws_url = self.validate_ws_url()?;
        let channel = self
            .chat
            .channel
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(DEFAULT_CHAT_CHANNEL)
            .to_owned();
        validate_chat_handle("chat.channel", &channel)?;
        let identity_dir = match self
            .chat
            .identity_dir
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            Some(dir) => PathBuf::from(dir),
            None => default_chat_identity_dir().ok_or(ConfigError::InvalidValue {
                field: "chat.identity_dir",
                reason: "no default config directory is available; set chat.identity_dir"
                    .to_owned(),
            })?,
        };
        let claim_window = std::time::Duration::from_millis(
            self.chat.claim_window_ms.unwrap_or(DEFAULT_CLAIM_WINDOW_MS),
        );
        let liveness_timeout = std::time::Duration::from_millis(
            self.chat
                .liveness_timeout_ms
                .unwrap_or(DEFAULT_LIVENESS_TIMEOUT_MS),
        );
        Ok(ValidatedChatConfig {
            ws_url,
            channel,
            identity_dir,
            claim_window,
            liveness_timeout,
        })
    }
}

/// A chat channel or wire handle must be an `@`-prefixed name. Light validation;
/// the hub is the final authority.
pub fn validate_chat_handle(field: &'static str, value: &str) -> Result<(), ConfigError> {
    if !value.starts_with('@') || value.len() < 2 {
        return Err(ConfigError::InvalidValue {
            field,
            reason: format!("must be an @-prefixed name, got {value:?}"),
        });
    }
    Ok(())
}

/// Default per-handle key directory: `<config-dir>/<command>/chat-keys`.
pub fn default_chat_identity_dir() -> Option<PathBuf> {
    let base_dirs = BaseDirs::new()?;
    Some(base_dirs.config_dir().join(COMMAND_NAME).join("chat-keys"))
}

/// Default router agent identity key: `<config-dir>/<command>/router-agent.key`.
/// One stable Ed25519 key for the daemon's router connections (replaces the old
/// `auth_token` bearer credential under SPEC-012). The hub TOFU-enrols it.
pub fn default_router_identity_path() -> Option<PathBuf> {
    let base_dirs = BaseDirs::new()?;
    Some(base_dirs.config_dir().join(COMMAND_NAME).join("router-agent.key"))
}

pub fn default_config_file() -> Option<PathBuf> {
    let base_dirs = BaseDirs::new()?;
    Some(
        base_dirs
            .config_dir()
            .join(COMMAND_NAME)
            .join("config.toml"),
    )
}

pub fn validate_agent_id_prefix(value: &str) -> Result<(), ConfigError> {
    validate_grammar(
        "agent.agent_id_prefix",
        value,
        63,
        |character| character.is_ascii_alphanumeric(),
        |character| character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-'),
    )
}

pub fn validate_capability_name(value: &str) -> Result<(), ConfigError> {
    validate_grammar(
        "capability",
        value,
        128,
        |character| character.is_ascii_alphanumeric(),
        |character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | ':' | '/' | '-')
        },
    )
}

pub fn validate_dialect_id(value: &str) -> Result<(), ConfigError> {
    validate_grammar(
        "dialect",
        value,
        64,
        |character| character.is_ascii_alphabetic(),
        |character| character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-'),
    )
}

fn load_file_backed_config(config_file: Option<PathBuf>) -> Result<AppConfig, ConfigError> {
    let mut builder = Config::builder()
        .set_default("agent.agent_id_prefix", DEFAULT_AGENT_ID_PREFIX)?
        .set_default("daemon.bind", DEFAULT_DAEMON_BIND)?
        .set_default(
            "daemon.max_messages_per_handle",
            DEFAULT_MAX_MESSAGES_PER_HANDLE as u64,
        )?
        .set_default(
            "daemon.max_bytes_per_handle",
            DEFAULT_MAX_BYTES_PER_HANDLE as u64,
        )?
        .set_default("daemon.overflow_policy", DEFAULT_OVERFLOW_POLICY)?
        .set_default(
            "agent.auto_install_advertised",
            DEFAULT_AUTO_INSTALL_ADVERTISED,
        )?;

    if let Some(config_file) = config_file {
        builder = builder.add_source(File::from(config_file).required(false));
    }

    Ok(builder.build()?.try_deserialize()?)
}

fn apply_environment_overrides(config: &mut AppConfig) -> Result<(), ConfigError> {
    if let Some(value) = env_value("CBCL_ROUTER_WS") {
        config.router.ws_url = Some(value);
    }
    if let Some(value) = env_value("CBCL_ROUTER_AUTH_TOKEN") {
        config.router.auth_token = Some(value);
    }
    if let Some(value) = env_value("CBCL_CHAT_CHANNEL") {
        config.chat.channel = Some(value);
    }
    if let Some(value) = env_value("CBCL_CHAT_IDENTITY_DIR") {
        config.chat.identity_dir = Some(value);
    }
    if let Some(value) = env_value("CBCL_AGENT_ID_PREFIX") {
        config.agent.agent_id_prefix = value;
    }
    if let Some(value) = env_value("CBCL_AGENT_AUTO_INSTALL_ADVERTISED") {
        config.agent.auto_install_advertised =
            parse_bool_env("CBCL_AGENT_AUTO_INSTALL_ADVERTISED", &value)?;
    }
    if let Some(value) = env_value("CBCL_DAEMON_BIND") {
        config.daemon.bind = value;
    }
    if let Some(value) = env_value("CBCL_DAEMON_MAX_MESSAGES_PER_HANDLE") {
        config.daemon.max_messages_per_handle =
            parse_positive_env_usize("CBCL_DAEMON_MAX_MESSAGES_PER_HANDLE", &value)?;
    }
    if let Some(value) = env_value("CBCL_DAEMON_MAX_BYTES_PER_HANDLE") {
        config.daemon.max_bytes_per_handle =
            parse_positive_env_usize("CBCL_DAEMON_MAX_BYTES_PER_HANDLE", &value)?;
    }
    if let Some(value) = env_value("CBCL_DAEMON_OVERFLOW_POLICY") {
        config.daemon.overflow_policy = value;
    }

    Ok(())
}

fn env_value(name: &str) -> Option<String> {
    env::var(name).ok()
}

fn parse_bool_env(var: &'static str, value: &str) -> Result<bool, ConfigError> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(ConfigError::InvalidEnv {
            var,
            reason: "expected one of 1/0, true/false, yes/no, on/off".to_owned(),
        }),
    }
}

fn parse_positive_env_usize(var: &'static str, value: &str) -> Result<usize, ConfigError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ConfigError::InvalidEnv {
            var,
            reason: "expected a positive base-10 integer".to_owned(),
        });
    }

    let parsed = value
        .parse::<usize>()
        .map_err(|error| ConfigError::InvalidEnv {
            var,
            reason: error.to_string(),
        })?;

    if parsed == 0 {
        return Err(ConfigError::InvalidEnv {
            var,
            reason: "value must be positive".to_owned(),
        });
    }

    Ok(parsed)
}

fn validate_daemon_bind(value: &str) -> Result<(), ConfigError> {
    let addr = value
        .parse::<SocketAddr>()
        .map_err(|error| ConfigError::InvalidValue {
            field: "daemon.bind",
            reason: error.to_string(),
        })?;

    if !addr.ip().is_loopback() {
        return Err(ConfigError::InvalidValue {
            field: "daemon.bind",
            reason: "address must be loopback-only".to_owned(),
        });
    }

    Ok(())
}

fn validate_positive(field: &'static str, value: usize) -> Result<(), ConfigError> {
    if value == 0 {
        return Err(ConfigError::InvalidValue {
            field,
            reason: "value must be positive".to_owned(),
        });
    }

    Ok(())
}

fn validate_grammar(
    field: &'static str,
    value: &str,
    max_len: usize,
    first_allowed: impl Fn(char) -> bool,
    rest_allowed: impl Fn(char) -> bool,
) -> Result<(), ConfigError> {
    if value.is_empty() {
        return Err(ConfigError::InvalidValue {
            field,
            reason: "value must not be empty".to_owned(),
        });
    }

    if value.len() > max_len {
        return Err(ConfigError::InvalidValue {
            field,
            reason: format!("value must be at most {max_len} bytes"),
        });
    }

    if !value.is_ascii() {
        return Err(ConfigError::InvalidValue {
            field,
            reason: "value must be ASCII".to_owned(),
        });
    }

    let mut chars = value.chars();
    let first = chars
        .next()
        .expect("value was checked as non-empty before grammar validation");
    if !first_allowed(first) {
        return Err(ConfigError::InvalidValue {
            field,
            reason: "first character is not allowed".to_owned(),
        });
    }

    if chars.any(|character| !rest_allowed(character)) {
        return Err(ConfigError::InvalidValue {
            field,
            reason: "contains an unsupported character".to_owned(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        env, fs,
        sync::{Mutex, MutexGuard},
    };

    use tempfile::TempDir;

    use crate::constants::{
        DEFAULT_AGENT_ID_PREFIX, DEFAULT_DAEMON_BIND, DEFAULT_MAX_BYTES_PER_HANDLE,
        DEFAULT_MAX_MESSAGES_PER_HANDLE, DEFAULT_OVERFLOW_POLICY,
    };

    use super::{
        AppConfig, ChatConfig, ConfigError, RouterConfig, Transport, validate_capability_name,
        validate_dialect_id,
    };

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn config_with_ws(url: &str) -> AppConfig {
        AppConfig {
            router: RouterConfig {
                ws_url: Some(url.to_owned()),
                auth_token: Some("shr_token".to_owned()),
            },
            ..AppConfig::default()
        }
    }

    #[test]
    fn transport_is_chat_only_for_chat_v1_path() {
        assert_eq!(
            config_with_ws("wss://hub.example/chat/v1")
                .transport()
                .unwrap(),
            Transport::Chat
        );
        assert_eq!(
            config_with_ws("wss://hub.example/agent/v1")
                .transport()
                .unwrap(),
            Transport::Router
        );
        // A chat-ish prefix that isn't exactly /chat/v1 stays router.
        assert_eq!(
            config_with_ws("wss://hub.example/chat/v2")
                .transport()
                .unwrap(),
            Transport::Router
        );
    }

    #[test]
    fn validate_chat_applies_defaults() {
        let chat = config_with_ws("wss://hub.example/chat/v1")
            .validate_chat()
            .expect("chat config should validate");
        assert_eq!(chat.channel, super::DEFAULT_CHAT_CHANNEL);
        assert!(chat.identity_dir.ends_with("chat-keys"));
    }

    #[test]
    fn validate_chat_overrides_channel_and_dir() {
        let config = AppConfig {
            router: RouterConfig {
                ws_url: Some("ws://localhost:8080/chat/v1".to_owned()),
                auth_token: None,
            },
            chat: ChatConfig {
                channel: Some("@research".to_owned()),
                identity_dir: Some("/tmp/hark-keys".to_owned()),
                claim_window_ms: Some(250),
                liveness_timeout_ms: None,
            },
            ..AppConfig::default()
        };
        let chat = config.validate_chat().expect("validate");
        assert_eq!(chat.channel, "@research");
        assert_eq!(
            chat.identity_dir,
            std::path::PathBuf::from("/tmp/hark-keys")
        );
        // Δ overridden; T falls back to the default.
        assert_eq!(chat.claim_window, std::time::Duration::from_millis(250));
        assert_eq!(
            chat.liveness_timeout,
            std::time::Duration::from_millis(super::DEFAULT_LIVENESS_TIMEOUT_MS)
        );
        // Chat needs no auth token.
        assert_eq!(config.transport().unwrap(), Transport::Chat);
    }

    #[test]
    fn validate_chat_rejects_non_at_channel() {
        let config = AppConfig {
            chat: ChatConfig {
                channel: Some("general".to_owned()),
                identity_dir: None,
                claim_window_ms: None,
                liveness_timeout_ms: None,
            },
            ..config_with_ws("wss://hub.example/chat/v1")
        };
        assert!(matches!(
            config.validate_chat(),
            Err(ConfigError::InvalidValue {
                field: "chat.channel",
                ..
            })
        ));
    }

    const ENV_VARS: &[&str] = &[
        "CBCL_ROUTER_WS",
        "CBCL_ROUTER_AUTH_TOKEN",
        "CBCL_AGENT_ID_PREFIX",
        "CBCL_DAEMON_BIND",
        "CBCL_DAEMON_MAX_MESSAGES_PER_HANDLE",
        "CBCL_DAEMON_MAX_BYTES_PER_HANDLE",
        "CBCL_DAEMON_OVERFLOW_POLICY",
    ];

    #[test]
    fn loads_built_in_defaults_without_router_config() {
        let _guard = clean_env();

        let config = AppConfig::load_from(None).expect("defaults should load");

        assert_eq!(config.router.ws_url, None);
        assert_eq!(config.router.auth_token, None);
        assert_eq!(config.agent.agent_id_prefix, DEFAULT_AGENT_ID_PREFIX);
        assert_eq!(config.daemon.bind, DEFAULT_DAEMON_BIND);
        assert_eq!(
            config.daemon.max_messages_per_handle,
            DEFAULT_MAX_MESSAGES_PER_HANDLE
        );
        assert_eq!(
            config.daemon.max_bytes_per_handle,
            DEFAULT_MAX_BYTES_PER_HANDLE
        );
        assert_eq!(config.daemon.overflow_policy, DEFAULT_OVERFLOW_POLICY);
    }

    #[test]
    fn loads_config_file_over_defaults() {
        let _guard = clean_env();
        let (_temp_dir, config_path) = write_config(
            r#"
                [router]
                ws_url = "wss://router.example/agent/v1"
                auth_token = "shr_file.secret"

                [agent]
                agent_id_prefix = "file-agent"

                [daemon]
                bind = "127.0.0.1:9876"
                max_messages_per_handle = 12
                max_bytes_per_handle = 34
                overflow_policy = "reject_new_and_close"
            "#,
        );

        let config = AppConfig::load_from(Some(config_path)).expect("file config should load");

        assert_eq!(
            config.router.ws_url.as_deref(),
            Some("wss://router.example/agent/v1")
        );
        assert_eq!(config.router.auth_token.as_deref(), Some("shr_file.secret"));
        assert_eq!(config.agent.agent_id_prefix, "file-agent");
        assert_eq!(config.daemon.bind, "127.0.0.1:9876");
        assert_eq!(config.daemon.max_messages_per_handle, 12);
        assert_eq!(config.daemon.max_bytes_per_handle, 34);
    }

    #[test]
    fn environment_overrides_config_file() {
        let _guard = clean_env();
        let (_temp_dir, config_path) = write_config(
            r#"
                [router]
                ws_url = "wss://router.example/agent/v1"
                auth_token = "shr_file.secret"

                [agent]
                agent_id_prefix = "file-agent"

                [daemon]
                bind = "127.0.0.1:9876"
                max_messages_per_handle = 12
                max_bytes_per_handle = 34
                overflow_policy = "reject_new_and_close"
            "#,
        );
        set_env("CBCL_ROUTER_WS", "ws://env.example/agent/v1");
        set_env("CBCL_ROUTER_AUTH_TOKEN", "shr_env.secret");
        set_env("CBCL_AGENT_ID_PREFIX", "env-agent");
        set_env("CBCL_DAEMON_BIND", "[::1]:1234");
        set_env("CBCL_DAEMON_MAX_MESSAGES_PER_HANDLE", "56");
        set_env("CBCL_DAEMON_MAX_BYTES_PER_HANDLE", "78");

        let config = AppConfig::load_from(Some(config_path)).expect("env override should load");

        assert_eq!(
            config.router.ws_url.as_deref(),
            Some("ws://env.example/agent/v1")
        );
        assert_eq!(config.router.auth_token.as_deref(), Some("shr_env.secret"));
        assert_eq!(config.agent.agent_id_prefix, "env-agent");
        assert_eq!(config.daemon.bind, "[::1]:1234");
        assert_eq!(config.daemon.max_messages_per_handle, 56);
        assert_eq!(config.daemon.max_bytes_per_handle, 78);
    }

    #[test]
    fn rejects_invalid_numeric_environment_overrides() {
        let _guard = clean_env();
        set_env("CBCL_DAEMON_MAX_MESSAGES_PER_HANDLE", "0");

        let error = AppConfig::load_from(None).expect_err("zero queue limit should fail");

        assert!(matches!(
            error,
            ConfigError::InvalidEnv {
                var: "CBCL_DAEMON_MAX_MESSAGES_PER_HANDLE",
                ..
            }
        ));
    }

    #[test]
    fn validates_daemon_runtime_without_requiring_router_config() {
        let _guard = clean_env();
        let config = AppConfig::load_from(None).expect("defaults should load");

        config
            .validate_daemon_runtime()
            .expect("default daemon config should be valid");

        assert!(matches!(
            config.validate_router(),
            Err(ConfigError::MissingRouterWsUrl)
        ));
    }

    #[test]
    fn rejects_non_loopback_daemon_bind() {
        let mut config = AppConfig::default();
        config.daemon.bind = "0.0.0.0:8080".to_owned();

        let error = config
            .validate_daemon_runtime()
            .expect_err("public bind should fail");

        assert!(matches!(
            error,
            ConfigError::InvalidValue {
                field: "daemon.bind",
                ..
            }
        ));
    }

    #[test]
    fn rejects_invalid_queue_limits() {
        let mut config = AppConfig::default();
        config.daemon.max_bytes_per_handle = 0;

        let error = config
            .validate_daemon_runtime()
            .expect_err("zero byte limit should fail");

        assert!(matches!(
            error,
            ConfigError::InvalidValue {
                field: "daemon.max_bytes_per_handle",
                ..
            }
        ));
    }

    #[test]
    fn rejects_unsupported_overflow_policy() {
        let mut config = AppConfig::default();
        config.daemon.overflow_policy = "drop_oldest".to_owned();

        let error = config
            .validate_daemon_runtime()
            .expect_err("unsupported policy should fail");

        assert!(matches!(
            error,
            ConfigError::InvalidValue {
                field: "daemon.overflow_policy",
                ..
            }
        ));
    }

    #[test]
    fn validates_agent_id_prefix_grammar() {
        let mut config = AppConfig::default();
        config.agent.agent_id_prefix = "agent_1.alpha-beta".to_owned();
        config
            .validate_daemon_runtime()
            .expect("valid prefix should pass");

        config.agent.agent_id_prefix = "-agent".to_owned();
        assert!(matches!(
            config.validate_daemon_runtime(),
            Err(ConfigError::InvalidValue {
                field: "agent.agent_id_prefix",
                ..
            })
        ));
    }

    #[test]
    fn validates_capability_and_dialect_grammars() {
        validate_capability_name("code:edit/test-1").expect("valid capability should pass");
        validate_dialect_id("cbcl-router_1").expect("valid dialect should pass");

        assert!(validate_capability_name(":code").is_err());
        assert!(validate_capability_name("code space").is_err());
        assert!(validate_dialect_id("1elf").is_err());
        assert!(validate_dialect_id("elf:router").is_err());
    }

    #[test]
    fn validates_router_config_lazily() {
        let mut config = AppConfig::default();
        assert!(matches!(
            config.validate_router(),
            Err(ConfigError::MissingRouterWsUrl)
        ));

        config.router.ws_url = Some("https://router.example/agent/v1".to_owned());
        config.router.auth_token = Some("shr_test.secret".to_owned());
        assert!(matches!(
            config.validate_router(),
            Err(ConfigError::InvalidRouterWsUrl(_))
        ));

        // SPEC-012 REQ-009: the router no longer requires a bearer token — a
        // config with no auth_token now validates (identity is per-frame Ed25519).
        config.router.ws_url = Some("wss://router.example/agent/v1".to_owned());
        config.router.auth_token = None;
        let validated = config
            .validate_router()
            .expect("router config should pass without an auth token");
        assert_eq!(validated.ws_url.as_str(), "wss://router.example/agent/v1");
        assert_eq!(validated.auth_token, "");

        // a legacy auth_token is accepted but ignored.
        config.router.auth_token = Some("shr_test.secret".to_owned());
        let validated = config.validate_router().expect("router config should pass");
        assert_eq!(validated.ws_url.as_str(), "wss://router.example/agent/v1");
    }

    #[test]
    fn redacts_router_auth_token_in_debug_output() {
        let config = AppConfig {
            router: super::RouterConfig {
                ws_url: Some("wss://router.example/agent/v1".to_owned()),
                auth_token: Some("shr_secret.do-not-print".to_owned()),
            },
            ..AppConfig::default()
        };

        let debug = format!("{config:?}");

        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("shr_secret.do-not-print"));

        let validated = config
            .validate_router()
            .expect("router config should validate");
        let debug = format!("{validated:?}");

        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("shr_secret.do-not-print"));
    }

    fn write_config(contents: &str) -> (TempDir, std::path::PathBuf) {
        let temp_dir = TempDir::new().expect("temp dir should be created");
        let config_path = temp_dir.path().join("config.toml");
        fs::write(&config_path, contents).expect("config file should be written");
        (temp_dir, config_path)
    }

    fn clean_env() -> MutexGuard<'static, ()> {
        let guard = ENV_LOCK.lock().expect("env lock should not be poisoned");
        for name in ENV_VARS {
            remove_env(name);
        }
        guard
    }

    fn set_env(name: &str, value: &str) {
        // Tests serialize access to process environment with ENV_LOCK.
        unsafe {
            env::set_var(name, value);
        }
    }

    fn remove_env(name: &str) {
        // Tests serialize access to process environment with ENV_LOCK.
        unsafe {
            env::remove_var(name);
        }
    }
}
