use crate::constants::{
    DEFAULT_AGENT_ID_PREFIX, DEFAULT_DAEMON_BIND, DEFAULT_MAX_BYTES_PER_HANDLE,
    DEFAULT_MAX_MESSAGES_PER_HANDLE, DEFAULT_OVERFLOW_POLICY,
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AppConfig {
    pub router: RouterConfig,
    pub agent: AgentConfig,
    pub daemon: DaemonConfig,
}

#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct RouterConfig {
    pub ws_url: Option<String>,
    pub auth_token: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AgentConfig {
    pub agent_id_prefix: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DaemonConfig {
    pub bind: String,
    pub max_messages_per_handle: usize,
    pub max_bytes_per_handle: usize,
    pub overflow_policy: String,
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
