#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[repr(i32)]
pub enum ExitCode {
    Success = 0,
    Usage = 2,
    DaemonNotRunning = 3,
    DaemonAlreadyRunning = 4,
    StaleDaemonState = 5,
    MissingAgentHandle = 6,
    AgentHandleUnavailable = 7,
    CbclValidation = 8,
    RouterConnection = 9,
    Timeout = 10,
    LocalAuth = 11,
    Internal = 12,
}

impl ExitCode {
    pub const fn as_i32(self) -> i32 {
        self as i32
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("{0}")]
    Usage(String),
    #[error("hark daemon is not running")]
    DaemonNotRunning,
    #[error("daemon is already running")]
    DaemonAlreadyRunning,
    #[error("stale daemon state")]
    StaleDaemonState,
    #[error("CBCL_AGENT_HANDLE is not set")]
    MissingAgentHandle,
    #[error("agent handle is not active or usable")]
    AgentHandleUnavailable,
    #[error("CBCL validation failed")]
    CbclValidation,
    #[error("router connection failed")]
    RouterConnection,
    #[error("operation timed out")]
    Timeout,
    #[error("local daemon authentication failed")]
    LocalAuth,
    #[error("{0}")]
    Internal(String),
}

impl AppError {
    pub const fn exit_code(&self) -> ExitCode {
        match self {
            Self::Usage(_) => ExitCode::Usage,
            Self::DaemonNotRunning => ExitCode::DaemonNotRunning,
            Self::DaemonAlreadyRunning => ExitCode::DaemonAlreadyRunning,
            Self::StaleDaemonState => ExitCode::StaleDaemonState,
            Self::MissingAgentHandle => ExitCode::MissingAgentHandle,
            Self::AgentHandleUnavailable => ExitCode::AgentHandleUnavailable,
            Self::CbclValidation => ExitCode::CbclValidation,
            Self::RouterConnection => ExitCode::RouterConnection,
            Self::Timeout => ExitCode::Timeout,
            Self::LocalAuth => ExitCode::LocalAuth,
            Self::Internal(_) => ExitCode::Internal,
        }
    }
}

pub type AppResult<T> = Result<T, AppError>;

#[cfg(test)]
mod tests {
    use super::{AppError, ExitCode};

    #[test]
    fn maps_errors_to_stable_exit_codes() {
        let cases = [
            (AppError::Usage("bad flag".into()), ExitCode::Usage),
            (AppError::DaemonNotRunning, ExitCode::DaemonNotRunning),
            (
                AppError::DaemonAlreadyRunning,
                ExitCode::DaemonAlreadyRunning,
            ),
            (AppError::StaleDaemonState, ExitCode::StaleDaemonState),
            (AppError::MissingAgentHandle, ExitCode::MissingAgentHandle),
            (
                AppError::AgentHandleUnavailable,
                ExitCode::AgentHandleUnavailable,
            ),
            (AppError::CbclValidation, ExitCode::CbclValidation),
            (AppError::RouterConnection, ExitCode::RouterConnection),
            (AppError::Timeout, ExitCode::Timeout),
            (AppError::LocalAuth, ExitCode::LocalAuth),
            (AppError::Internal("boom".into()), ExitCode::Internal),
        ];

        for (error, exit_code) in cases {
            assert_eq!(error.exit_code(), exit_code);
        }
    }

    #[test]
    fn exit_code_values_match_cli_contract() {
        assert_eq!(ExitCode::Success.as_i32(), 0);
        assert_eq!(ExitCode::Usage.as_i32(), 2);
        assert_eq!(ExitCode::DaemonNotRunning.as_i32(), 3);
        assert_eq!(ExitCode::DaemonAlreadyRunning.as_i32(), 4);
        assert_eq!(ExitCode::StaleDaemonState.as_i32(), 5);
        assert_eq!(ExitCode::MissingAgentHandle.as_i32(), 6);
        assert_eq!(ExitCode::AgentHandleUnavailable.as_i32(), 7);
        assert_eq!(ExitCode::CbclValidation.as_i32(), 8);
        assert_eq!(ExitCode::RouterConnection.as_i32(), 9);
        assert_eq!(ExitCode::Timeout.as_i32(), 10);
        assert_eq!(ExitCode::LocalAuth.as_i32(), 11);
        assert_eq!(ExitCode::Internal.as_i32(), 12);
    }
}
