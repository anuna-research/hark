use std::{env, fmt, net::SocketAddr, path::PathBuf};

use config::{Config, File};
use directories::BaseDirs;
use serde::Deserialize;
use url::Url;

use crate::constants::{
    COMMAND_NAME, DEFAULT_AGENT_ID_PREFIX, DEFAULT_DAEMON_BIND, DEFAULT_MAX_BYTES_PER_HANDLE,
    DEFAULT_MAX_MESSAGES_PER_HANDLE, DEFAULT_OVERFLOW_POLICY,
};

#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
#[serde(default)]
pub struct AppConfig {
    pub router: RouterConfig,
    pub agent: AgentConfig,
    pub daemon: DaemonConfig,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Default)]
#[serde(default)]
pub struct RouterConfig {
    pub ws_url: Option<String>,
    pub auth_token: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
#[serde(default)]
pub struct AgentConfig {
    pub agent_id_prefix: String,
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
            agent: AgentConfig {
                agent_id_prefix: DEFAULT_AGENT_ID_PREFIX.to_owned(),
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

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            agent_id_prefix: DEFAULT_AGENT_ID_PREFIX.to_owned(),
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

    pub fn validate_router(&self) -> Result<ValidatedRouterConfig, ConfigError> {
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

        let auth_token = self
            .router
            .auth_token
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .ok_or(ConfigError::MissingRouterAuthToken)?;

        Ok(ValidatedRouterConfig {
            ws_url,
            auth_token: auth_token.to_owned(),
        })
    }
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
        .set_default("daemon.overflow_policy", DEFAULT_OVERFLOW_POLICY)?;

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
    if let Some(value) = env_value("CBCL_AGENT_ID_PREFIX") {
        config.agent.agent_id_prefix = value;
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

    use super::{AppConfig, ConfigError, validate_capability_name, validate_dialect_id};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

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

        config.router.ws_url = Some("wss://router.example/agent/v1".to_owned());
        config.router.auth_token = None;
        assert!(matches!(
            config.validate_router(),
            Err(ConfigError::MissingRouterAuthToken)
        ));

        config.router.auth_token = Some("shr_test.secret".to_owned());
        let validated = config.validate_router().expect("router config should pass");
        assert_eq!(validated.ws_url.as_str(), "wss://router.example/agent/v1");
        assert_eq!(validated.auth_token, "shr_test.secret");
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
