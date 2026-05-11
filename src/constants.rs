pub const COMMAND_NAME: &str = "hark";
pub const LOCAL_API_VERSION: u16 = 2;

pub const DEFAULT_AGENT_ID_PREFIX: &str = "local-agent";
pub const DEFAULT_DAEMON_BIND: &str = "127.0.0.1:0";
pub const DEFAULT_MAX_MESSAGES_PER_HANDLE: usize = 1_000;
pub const DEFAULT_MAX_BYTES_PER_HANDLE: usize = 64 * 1024 * 1024;
pub const DEFAULT_OVERFLOW_POLICY: &str = "reject_new_and_close";
pub const DEFAULT_PROGRESS_DIALECT: &str = "elf";
pub const MAX_RECV_TIMEOUT_MS: u64 = 7_776_000_000;
