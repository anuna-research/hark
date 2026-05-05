use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::constants::{COMMAND_NAME, DEFAULT_PROGRESS_DIALECT};
use crate::errors::{AppError, AppResult};

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
            DaemonCommand::Start => not_implemented("daemon start"),
            DaemonCommand::Run => not_implemented("daemon run"),
            DaemonCommand::Status => not_implemented("daemon status"),
            DaemonCommand::Stop => not_implemented("daemon stop"),
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
