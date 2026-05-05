use std::{
    fs,
    process::{Command as ProcessCommand, Stdio},
    time::{Duration, Instant},
};

use clap::{Args, Parser, Subcommand, ValueEnum};
use tokio::net::TcpListener;

use crate::constants::{COMMAND_NAME, DEFAULT_PROGRESS_DIALECT};
use crate::daemon::{
    AgentStore, AgentStoreConfig, DiscoveryRecord, RuntimePaths, acquire_daemon_lock,
    create_runtime_dir, generate_daemon_token, load_discovery_record, probe_lock_available,
    resolve_runtime_paths, write_discovery_record,
};
use crate::errors::{AppError, AppResult};
use crate::local_api::{ClientPingError, LocalApiClient, serve_local_api_with_agents};

#[derive(Debug, Parser)]
#[command(name = COMMAND_NAME, version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    #[command(subcommand)]
    Daemon(DaemonCommand),
    Init(InitArgs),
    Recv(RecvArgs),
    Reply(MessageInputArgs),
    Error(MessageInputArgs),
    Progress(ProgressArgs),
    Close,
}

#[derive(Debug, Subcommand)]
pub enum DaemonCommand {
    Start,
    Run,
    Status,
    Stop,
}

#[derive(Debug, Args)]
pub struct InitArgs {
    #[arg(long = "capability", required = true)]
    pub capabilities: Vec<String>,
    #[arg(long = "dialect")]
    pub dialects: Vec<String>,
    #[arg(long = "json")]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct RecvArgs {
    #[arg(long = "timeout")]
    pub timeout: Option<String>,
}

#[derive(Debug, Args)]
pub struct MessageInputArgs {
    pub message: Option<String>,
}

#[derive(Debug, Args)]
pub struct ProgressArgs {
    #[arg(long = "thread")]
    pub thread: String,
    #[arg(long = "text")]
    pub text: Option<String>,
    #[arg(long = "dialect", default_value = DEFAULT_PROGRESS_DIALECT)]
    pub dialect: String,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
pub enum SendKind {
    Reply,
    Error,
    Progress,
}

pub async fn run(cli: Cli) -> AppResult<()> {
    match cli.command {
        Command::Daemon(command) => match command {
            DaemonCommand::Start => daemon_start().await,
            DaemonCommand::Run => daemon_run().await,
            DaemonCommand::Status => daemon_status().await,
            DaemonCommand::Stop => daemon_stop().await,
        },
        Command::Init(_) => not_implemented("init"),
        Command::Recv(_) => not_implemented("recv"),
        Command::Reply(_) => not_implemented("reply"),
        Command::Error(_) => not_implemented("error"),
        Command::Progress(_) => not_implemented("progress"),
        Command::Close => not_implemented("close"),
    }
}

fn not_implemented(command: &str) -> AppResult<()> {
    Err(AppError::Internal(format!(
        "{command} is not implemented yet"
    )))
}

async fn daemon_run() -> AppResult<()> {
    let config = crate::config::AppConfig::load()
        .map_err(|error| AppError::Usage(format!("failed to load config: {error}")))?;
    config
        .validate_daemon_runtime()
        .map_err(|error| AppError::Usage(format!("invalid daemon config: {error}")))?;

    let paths = resolve_runtime_paths()
        .map_err(|error| AppError::Internal(format!("failed to resolve runtime dir: {error}")))?;
    create_runtime_dir(&paths.runtime_dir)
        .map_err(|error| AppError::Internal(format!("failed to create runtime dir: {error}")))?;

    let lock = match acquire_daemon_lock(&paths) {
        Ok(lock) => lock,
        Err(error) if is_lock_busy(&error) => {
            return Err(AppError::DaemonAlreadyRunning);
        }
        Err(error) => {
            return Err(AppError::Internal(format!(
                "failed to acquire daemon lock: {error}"
            )));
        }
    };

    let listener = TcpListener::bind(&config.daemon.bind)
        .await
        .map_err(|error| AppError::Internal(format!("failed to bind local API: {error}")))?;
    let addr = listener
        .local_addr()
        .map_err(|error| AppError::Internal(format!("failed to read local API addr: {error}")))?;
    if !addr.ip().is_loopback() {
        return Err(AppError::Usage(
            "daemon bind address must be loopback-only".to_owned(),
        ));
    }

    let record = DiscoveryRecord::current(addr, generate_daemon_token());
    write_discovery_record(&paths, &record).map_err(|error| {
        AppError::Internal(format!("failed to write daemon discovery: {error}"))
    })?;

    let agents = AgentStore::new(AgentStoreConfig::from_config(&config));
    let result =
        serve_local_api_with_agents(listener, record, Some(paths.discovery_file.clone()), agents)
            .await;
    drop(lock);

    result.map_err(|error| AppError::Internal(format!("local API server failed: {error}")))
}

async fn daemon_start() -> AppResult<()> {
    let paths = resolve_runtime_paths()
        .map_err(|error| AppError::Internal(format!("failed to resolve runtime dir: {error}")))?;
    create_runtime_dir(&paths.runtime_dir)
        .map_err(|error| AppError::Internal(format!("failed to create runtime dir: {error}")))?;

    if let Some(record) = load_discovery_record(&paths)
        .map_err(|error| AppError::Internal(format!("failed to read daemon discovery: {error}")))?
    {
        match ping_record(&record).await {
            Ok(_) => return Ok(()),
            Err(ClientPingError::AuthFailure) => return Err(AppError::LocalAuth),
            Err(ClientPingError::ApiIncompatible { .. }) => {
                return Err(AppError::Internal(
                    "daemon_api_incompatible: restart the daemon with the current binary"
                        .to_owned(),
                ));
            }
            Err(_) => cleanup_stale_if_lock_free(&paths)?,
        }
    }

    let current_exe = std::env::current_exe().map_err(|error| {
        AppError::Internal(format!("failed to locate current executable: {error}"))
    })?;
    ProcessCommand::new(current_exe)
        .args(["daemon", "run"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| AppError::Internal(format!("failed to spawn daemon: {error}")))?;

    wait_for_daemon_ready(&paths, Duration::from_secs(10)).await
}

async fn daemon_status() -> AppResult<()> {
    let paths = resolve_runtime_paths()
        .map_err(|error| AppError::Internal(format!("failed to resolve runtime dir: {error}")))?;
    let Some(record) = load_discovery_record(&paths)
        .map_err(|error| AppError::Internal(format!("failed to read daemon discovery: {error}")))?
    else {
        println!("daemon: not running");
        return Err(AppError::DaemonNotRunning);
    };

    match ping_record(&record).await {
        Ok(client) => {
            let agents = client
                .agents()
                .await
                .map_err(|error| map_client_error(error, "daemon status failed"))?;
            println!("daemon: running");
            println!("addr: {}", agents.daemon.addr);
            println!("version: {}", agents.daemon.version);
            println!("api_version: {}", agents.daemon.api_version);
            println!("agents: {}", agents.agents.len());
            for agent in agents.agents {
                println!(
                    "{} {} queued_messages={} queued_bytes={}",
                    agent.agent_handle, agent.state, agent.queued_messages, agent.queued_bytes
                );
            }
            Ok(())
        }
        Err(ClientPingError::AuthFailure) => {
            eprintln!("daemon: local authentication failed");
            Err(AppError::LocalAuth)
        }
        Err(ClientPingError::ApiIncompatible {
            daemon_version,
            daemon_api_version,
            cli_api_version,
        }) => {
            eprintln!("daemon_api_incompatible");
            eprintln!("cli_api_version: {cli_api_version}");
            eprintln!("daemon_api_version: {daemon_api_version:?}");
            eprintln!("daemon_version: {daemon_version:?}");
            Err(AppError::Internal(
                "daemon_api_incompatible: restart the daemon with the current binary".to_owned(),
            ))
        }
        Err(_) => {
            if probe_lock_available(&paths).map_err(|error| {
                AppError::Internal(format!("failed to probe daemon lock: {error}"))
            })? {
                println!("daemon: stale discovery state (lock is free)");
            } else {
                println!("daemon: stale discovery state (lock is held)");
            }
            Err(AppError::StaleDaemonState)
        }
    }
}

async fn daemon_stop() -> AppResult<()> {
    let paths = resolve_runtime_paths()
        .map_err(|error| AppError::Internal(format!("failed to resolve runtime dir: {error}")))?;
    let Some(record) = load_discovery_record(&paths)
        .map_err(|error| AppError::Internal(format!("failed to read daemon discovery: {error}")))?
    else {
        return Ok(());
    };

    match ping_record(&record).await {
        Ok(client) => {
            client
                .stop()
                .await
                .map_err(|error| map_client_error(error, "daemon stop failed"))?;
            wait_for_daemon_stopped(&paths, &record, Duration::from_secs(5)).await
        }
        Err(ClientPingError::AuthFailure) => Err(AppError::LocalAuth),
        Err(ClientPingError::ApiIncompatible { .. }) => Err(AppError::Internal(
            "daemon_api_incompatible: restart the daemon with the current binary".to_owned(),
        )),
        Err(_) => {
            if probe_lock_available(&paths).map_err(|error| {
                AppError::Internal(format!("failed to probe daemon lock: {error}"))
            })? {
                remove_discovery_file(&paths)?;
                Ok(())
            } else {
                Err(AppError::StaleDaemonState)
            }
        }
    }
}

async fn ping_record(record: &DiscoveryRecord) -> Result<LocalApiClient, ClientPingError> {
    let client = LocalApiClient::from_discovery(record)
        .map_err(|error| ClientPingError::RequestFailed(error.to_string()))?;
    client.ping().await?;
    Ok(client)
}

async fn wait_for_daemon_ready(paths: &RuntimePaths, timeout: Duration) -> AppResult<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if Instant::now() >= deadline {
            return Err(AppError::Timeout);
        }

        if let Some(record) = load_discovery_record(paths).map_err(|error| {
            AppError::Internal(format!("failed to read daemon discovery: {error}"))
        })? {
            match ping_record(&record).await {
                Ok(_) => return Ok(()),
                Err(ClientPingError::AuthFailure) => return Err(AppError::LocalAuth),
                Err(ClientPingError::ApiIncompatible { .. }) => {
                    return Err(AppError::Internal(
                        "daemon_api_incompatible: restart the daemon with the current binary"
                            .to_owned(),
                    ));
                }
                Err(_) => {}
            }
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn wait_for_daemon_stopped(
    paths: &RuntimePaths,
    record: &DiscoveryRecord,
    timeout: Duration,
) -> AppResult<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if !paths.discovery_file.exists() {
            return Ok(());
        }
        if ping_record(record).await.is_err() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(AppError::Timeout);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn cleanup_stale_if_lock_free(paths: &RuntimePaths) -> AppResult<()> {
    if probe_lock_available(paths)
        .map_err(|error| AppError::Internal(format!("failed to probe daemon lock: {error}")))?
    {
        remove_discovery_file(paths)?;
        Ok(())
    } else {
        Err(AppError::StaleDaemonState)
    }
}

fn remove_discovery_file(paths: &RuntimePaths) -> AppResult<()> {
    match fs::remove_file(&paths.discovery_file) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(AppError::Internal(format!(
            "failed to remove stale daemon discovery: {error}"
        ))),
    }
}

fn map_client_error(error: ClientPingError, context: &str) -> AppError {
    match error {
        ClientPingError::AuthFailure => AppError::LocalAuth,
        ClientPingError::ApiIncompatible { .. } => AppError::Internal(
            "daemon_api_incompatible: restart the daemon with the current binary".to_owned(),
        ),
        ClientPingError::RequestFailed(_)
        | ClientPingError::UnexpectedStatus(_)
        | ClientPingError::DecodeFailed(_) => AppError::Internal(format!("{context}: {error}")),
    }
}

fn is_lock_busy(error: &crate::daemon::DiscoveryError) -> bool {
    matches!(error, crate::daemon::DiscoveryError::ReadDiscovery(io_error) if io_error.kind() == std::io::ErrorKind::WouldBlock)
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser};

    use super::{Cli, Command, DaemonCommand};

    #[test]
    fn command_tree_matches_mvp_surface() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_daemon_subcommands() {
        let cli = Cli::parse_from(["cbcl-router-client", "daemon", "run"]);
        assert!(matches!(cli.command, Command::Daemon(DaemonCommand::Run)));

        let cli = Cli::parse_from(["cbcl-router-client", "daemon", "start"]);
        assert!(matches!(cli.command, Command::Daemon(DaemonCommand::Start)));
    }

    #[test]
    fn parses_init_arguments() {
        let cli = Cli::parse_from([
            "cbcl-router-client",
            "init",
            "--capability",
            "code:edit",
            "--capability",
            "code:test",
            "--dialect",
            "elf",
            "--json",
        ]);

        let Command::Init(args) = cli.command else {
            panic!("expected init command");
        };

        assert_eq!(args.capabilities, ["code:edit", "code:test"]);
        assert_eq!(args.dialects, ["elf"]);
        assert!(args.json);
    }

    #[test]
    fn rejects_init_without_capability() {
        let error = Cli::try_parse_from(["cbcl-router-client", "init"]).unwrap_err();
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn parses_agent_workflow_commands() {
        let cli = Cli::parse_from(["cbcl-router-client", "recv", "--timeout", "30s"]);
        let Command::Recv(args) = cli.command else {
            panic!("expected recv command");
        };
        assert_eq!(args.timeout.as_deref(), Some("30s"));

        let cli = Cli::parse_from(["cbcl-router-client", "reply", "(reply @router \"ok\")"]);
        assert!(matches!(cli.command, Command::Reply(_)));

        let cli = Cli::parse_from([
            "cbcl-router-client",
            "progress",
            "--thread",
            "rcp-123",
            "--text",
            "running tests",
        ]);
        let Command::Progress(args) = cli.command else {
            panic!("expected progress command");
        };
        assert_eq!(args.thread, "rcp-123");
        assert_eq!(args.text.as_deref(), Some("running tests"));
        assert_eq!(args.dialect, "elf");

        let cli = Cli::parse_from(["cbcl-router-client", "close"]);
        assert!(matches!(cli.command, Command::Close));
    }
}
