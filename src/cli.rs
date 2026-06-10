use std::{
    fs,
    io::{IsTerminal, Read, Write},
    path::{Path, PathBuf},
    process::{Command as ProcessCommand, Stdio},
    time::{Duration, Instant},
};

use clap::{Args, Parser, Subcommand, ValueEnum};
use tokio::net::TcpListener;

use crate::cbcl_validation::{MessageKind, validate_for_emit, validate_for_send};
use crate::config::{
    SAMPLE_CONFIG, default_config_file, validate_dialect_id,
};
use crate::constants::{COMMAND_NAME, DEFAULT_PROGRESS_DIALECT, MAX_RECV_TIMEOUT_MS};
use crate::daemon::{
    AgentHandle, AgentStore, AgentStoreConfig, DiscoveryRecord, RuntimePaths, acquire_daemon_lock,
    create_runtime_dir, generate_daemon_token, load_discovery_record, probe_lock_available,
    resolve_runtime_paths, write_discovery_record,
};
use crate::errors::{AppError, AppResult};
use crate::local_api::{
    ClientPingError, CreateAgentRequest, LocalApiClient, LocalApiRequestError, MetaPublishRequest,
    MetaQueryRequest, MetaSubscribeRequest, SendMessageKind, SendRequest,
    serve_local_api_with_agents,
};

#[derive(Debug, Parser)]
#[command(name = COMMAND_NAME, version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    #[command(about = "Show or create the user configuration file")]
    #[command(subcommand)]
    Config(ConfigCommand),
    #[command(about = "Manage the per-user local daemon")]
    #[command(subcommand)]
    Daemon(DaemonCommand),
    #[command(
        about = "One-shot join: scaffold config if absent, start the daemon if needed, and join a chat channel"
    )]
    Join(JoinArgs),
    #[command(
        about = "Pair an agent into a channel via a memorable code: `hark pair \"<id>-word-word-word-word\"`"
    )]
    Pair(PairArgs),
    #[command(about = "Create an agent WebSocket and print the local handle")]
    Init(InitArgs),
    #[command(about = "Receive one CBCL message for the current agent handle")]
    Recv(RecvArgs),
    #[command(about = "Validate and send a CBCL reply message")]
    Reply(MessageInputArgs),
    #[command(about = "Validate and send a CBCL error message")]
    Error(MessageInputArgs),
    #[command(about = "Build and send a non-terminal progress message")]
    Progress(ProgressArgs),
    #[command(
        about = "Send a proactive message: plain text becomes (tell @channel \"…\"), a CBCL form passes through"
    )]
    Emit(MessageInputArgs),
    #[command(about = "Dialect discovery, subscription, and publication")]
    #[command(subcommand)]
    Dialect(DialectCommand),
    #[command(about = "Close the current agent handle")]
    Close,
}

#[derive(Debug, Subcommand)]
pub enum DialectCommand {
    #[command(about = "Publish a dialect to the router via (meta (teach @router <define>))")]
    Publish(DialectPublishArgs),
    #[command(about = "Ask the router whether it knows a dialect by name and install the teach-back")]
    Query(DialectQueryArgs),
    #[command(about = "List every dialect currently known to the router")]
    List,
    #[command(about = "Subscribe to router pushes for dialects matching a pattern")]
    Subscribe(DialectSubscribeArgs),
    #[command(about = "Drop the agent's dialect subscription on the router")]
    Unsubscribe,
}

#[derive(Debug, Args)]
pub struct DialectPublishArgs {
    #[arg(
        long = "define",
        help = "Complete `(define <name> ...)` CBCL form; if absent, read stdin until EOF"
    )]
    pub define: Option<String>,
    #[arg(long = "json", help = "Print JSON instead of `digest name` text")]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct DialectQueryArgs {
    #[arg(help = "Dialect name to ask the router about")]
    pub name: String,
    #[arg(long = "json", help = "Print JSON instead of `digest name` text")]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct DialectSubscribeArgs {
    #[arg(
        help = "Match pattern: exact name, `<prefix>*`, or `*` for all",
        default_value = "*"
    )]
    pub pattern: String,
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    #[command(about = "Print the platform config file path")]
    Path,
    #[command(about = "Print an example config.toml")]
    ShowExample,
    #[command(about = "Create an example config.toml if none exists")]
    Init,
}

#[derive(Debug, Subcommand)]
pub enum DaemonCommand {
    #[command(about = "Start the daemon in the background if needed")]
    Start,
    #[command(about = "Run the daemon in the foreground")]
    Run,
    #[command(about = "Show daemon and active agent status")]
    Status,
    #[command(about = "Stop the daemon")]
    Stop,
}

#[derive(Debug, Args)]
pub struct JoinArgs {
    #[arg(help = "Channel to join (@name)")]
    pub channel: String,
    #[arg(
        long = "as",
        help = "The agent's wire handle in the channel (@name)"
    )]
    pub as_handle: String,
    #[arg(
        long = "speak",
        value_delimiter = ',',
        help = "Dialect(s) to advertise (repeat or comma-separate); omit to advertise nothing"
    )]
    pub speak: Vec<String>,
    #[arg(
        long = "cap",
        help = "Capability token or invite for a private channel"
    )]
    pub cap: Option<String>,
    #[arg(
        long = "hub",
        help = "Chat hub WebSocket URL (…/chat/v1); defaults to the configured hub or the public hub"
    )]
    pub hub: Option<String>,
}

#[derive(Debug, Args)]
pub struct PairArgs {
    #[arg(
        help = "The pairing code from the web app: `<pairing-id>-word-word-word-word`"
    )]
    pub code: String,
    #[arg(
        long = "as",
        help = "Override the adder-set channel handle (@name); defaults to the record's name"
    )]
    pub as_handle: Option<String>,
    #[arg(
        long = "hub",
        help = "Chat hub WebSocket URL; defaults to the configured hub or the public hub"
    )]
    pub hub: Option<String>,
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Capability ≡ dialect: agents advertise the dialects they can
    /// perform. At least one is required.
    #[arg(
        long = "dialect",
        required = true,
        help = "Dialect id to advertise; repeat for multiple dialects"
    )]
    pub dialects: Vec<String>,
    #[arg(
        long = "handle",
        help = "Chat hub only: the agent's wire handle (@name); required on a chat hub, ignored by the router"
    )]
    pub handle: Option<String>,
    #[arg(
        long = "channel",
        help = "Chat hub only: channel to join (@name); defaults to the configured [chat].channel"
    )]
    pub channel: Option<String>,
    #[arg(
        long = "cap",
        help = "Chat hub only: capability token or invite for a private channel"
    )]
    pub cap: Option<String>,
    #[arg(long = "json", help = "Print JSON instead of shell exports")]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct RecvArgs {
    #[arg(long = "timeout", help = "Maximum wait, using ms, s, m, or h")]
    pub timeout: Option<String>,
}

#[derive(Debug, Args)]
pub struct MessageInputArgs {
    #[arg(help = "Complete CBCL message; if absent, read stdin until EOF")]
    pub message: Option<String>,
}

#[derive(Debug, Args)]
pub struct ProgressArgs {
    #[arg(long = "thread", help = "Receipt thread id from the dispatched ask")]
    pub thread: String,
    #[arg(long = "text", help = "Optional human-readable progress detail")]
    pub text: Option<String>,
    #[arg(
        long = "dialect",
        default_value = DEFAULT_PROGRESS_DIALECT,
        help = "Dialect wrapper for the generated progress message"
    )]
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
        Command::Config(command) => match command {
            ConfigCommand::Path => config_path(),
            ConfigCommand::ShowExample => config_show_example(),
            ConfigCommand::Init => config_init(),
        },
        Command::Daemon(command) => match command {
            DaemonCommand::Start => daemon_start().await,
            DaemonCommand::Run => daemon_run().await,
            DaemonCommand::Status => daemon_status().await,
            DaemonCommand::Stop => daemon_stop().await,
        },
        Command::Join(args) => join_command(args).await,
        Command::Pair(args) => pair_command(args).await,
        Command::Init(args) => init_command(args).await,
        Command::Recv(args) => recv_command(args).await,
        Command::Reply(args) => send_message_command(SendMessageKind::Reply, args).await,
        Command::Error(args) => send_message_command(SendMessageKind::Error, args).await,
        Command::Progress(args) => progress_command(args).await,
        Command::Emit(args) => emit_command(args).await,
        Command::Dialect(command) => match command {
            DialectCommand::Publish(args) => dialect_publish_command(args).await,
            DialectCommand::Query(args) => dialect_query_command(args).await,
            DialectCommand::List => dialect_list_command().await,
            DialectCommand::Subscribe(args) => dialect_subscribe_command(args).await,
            DialectCommand::Unsubscribe => dialect_unsubscribe_command().await,
        },
        Command::Close => close_command().await,
    }
}

fn config_path() -> AppResult<()> {
    let path = resolve_config_file()?;
    println!("{}", path.display());
    Ok(())
}

fn config_show_example() -> AppResult<()> {
    print!("{SAMPLE_CONFIG}");
    Ok(())
}

fn config_init() -> AppResult<()> {
    let path = resolve_config_file()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            AppError::Internal(format!(
                "failed to create config directory {}: {error}",
                parent.display()
            ))
        })?;
    }
    write_new_config_file(&path, SAMPLE_CONFIG)?;
    println!("{}", path.display());
    Ok(())
}

fn resolve_config_file() -> AppResult<PathBuf> {
    default_config_file()
        .ok_or_else(|| AppError::Internal("failed to resolve config file path".to_owned()))
}

fn write_new_config_file(path: &Path, contents: &str) -> AppResult<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            AppError::Usage(format!(
                "config file already exists: {}; refusing to overwrite",
                path.display()
            ))
        } else {
            AppError::Internal(format!(
                "failed to create config file {}: {error}",
                path.display()
            ))
        }
    })?;
    file.write_all(contents.as_bytes()).map_err(|error| {
        AppError::Internal(format!(
            "failed to write config file {}: {error}",
            path.display()
        ))
    })
}

/// REQ-002 (SPEC-016, ADR-001): the one-shot join. Composes config scaffolding,
/// daemon startup, and agent creation so an operator never edits TOML, learns
/// the `/chat/v1` transport rule, or `eval`s anything (NFR-002).
async fn join_command(args: JoinArgs) -> AppResult<()> {
    crate::config::validate_chat_handle("channel", &args.channel)
        .map_err(|error| AppError::Usage(error.to_string()))?;
    crate::config::validate_chat_handle("handle", &args.as_handle)
        .map_err(|error| AppError::Usage(error.to_string()))?;
    let mut seen = std::collections::HashSet::new();
    for dialect in &args.speak {
        validate_dialect_id(dialect).map_err(|error| AppError::Usage(error.to_string()))?;
        if !seen.insert(dialect) {
            return Err(AppError::Usage(format!("duplicate dialect: {dialect}")));
        }
    }

    // 1. Config: scaffold a chat config when none exists; otherwise verify the
    //    existing one actually points at a chat hub.
    let path = resolve_config_file()?;
    if !path.exists() {
        let hub = args
            .hub
            .as_deref()
            .unwrap_or(crate::constants::DEFAULT_CHAT_HUB_URL);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                AppError::Internal(format!(
                    "failed to create config directory {}: {error}",
                    parent.display()
                ))
            })?;
        }
        write_new_config_file(&path, &build_chat_config_toml(hub))?;
        eprintln!("scaffolded config at {}", path.display());
    }
    let config = crate::config::AppConfig::load()
        .map_err(|error| AppError::Usage(format!("failed to load config: {error}")))?;
    if let Some(hub) = args.hub.as_deref() {
        if config.router.ws_url.as_deref() != Some(hub) {
            return Err(AppError::Usage(format!(
                "config {} already points at {}; remove it or drop --hub",
                path.display(),
                config.router.ws_url.as_deref().unwrap_or("<unset>")
            )));
        }
    }
    let transport = config
        .transport()
        .map_err(|error| AppError::Usage(format!("invalid config: {error}")))?;
    if transport != crate::config::Transport::Chat {
        return Err(AppError::Usage(format!(
            "the configured ws_url is not a chat hub (its path must be /chat/v1); \
             edit {} or remove it and re-run `hark join`",
            path.display()
        )));
    }

    // 2. Daemon: idempotent start.
    daemon_start().await?;

    // 3. Join the channel. The new agent becomes the session's active handle
    //    (REQ-003) — no eval, no exported variable.
    let client = discover_live_client().await?;
    let response = client
        .create_agent(&CreateAgentRequest {
            dialects: args.speak,
            auto_install_advertised: None,
            channel: Some(args.channel.clone()),
            handle: Some(args.as_handle.clone()),
            cap: args.cap,
        })
        .await
        .map_err(map_local_api_request_error)?;

    for warning in &response.warnings {
        eprintln!("warning: {warning}");
    }
    let speaking = if response.dialects.is_empty() {
        "nothing".to_owned()
    } else {
        response.dialects.join(", ")
    };
    println!(
        "joined {} as {} · speaking: {speaking}",
        args.channel, args.as_handle
    );
    Ok(())
}

/// REQ-007/REQ-011 (SPEC-016): `hark pair "<code>"` — run the SPAKE2 pairing
/// handshake with the hub, then join the channel under the adder-set name with
/// the released invite cap. The four phrase words are the PAKE secret and never
/// leave this process. Composes config-scaffold + daemon-start like `join`.
async fn pair_command(args: PairArgs) -> AppResult<()> {
    let code = crate::pairing::parse_code(&args.code)
        .map_err(|error| AppError::Usage(error.to_string()))?;

    // 1. Config: scaffold a chat config when absent; verify it's a chat hub.
    let path = resolve_config_file()?;
    if !path.exists() {
        let hub = args
            .hub
            .as_deref()
            .unwrap_or(crate::constants::DEFAULT_CHAT_HUB_URL);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                AppError::Internal(format!(
                    "failed to create config directory {}: {error}",
                    parent.display()
                ))
            })?;
        }
        write_new_config_file(&path, &build_chat_config_toml(hub))?;
        eprintln!("scaffolded config at {}", path.display());
    }
    let config = crate::config::AppConfig::load()
        .map_err(|error| AppError::Usage(format!("failed to load config: {error}")))?;
    let hub_ws = args
        .hub
        .as_deref()
        .or(config.router.ws_url.as_deref())
        .ok_or_else(|| AppError::Usage("no chat hub configured; pass --hub <ws-url>".to_owned()))?;
    let pair_url = crate::pairing::client::pair_url_from(hub_ws)
        .map_err(|error| AppError::Usage(error.to_string()))?;

    // 2. Run the pairing handshake → the hub-released record (bound to K).
    let record = crate::pairing::client::run_pairing(&pair_url, &code)
        .await
        .map_err(map_pair_error)?;

    // 3. Encryption pin (R4-01): the cap's PRESENCE — not the advisory `enc`
    //    bit a hub could flip — decides private⇒encrypted. Surface a conflict.
    let cap = if record.has_cap() {
        if !record.enc {
            eprintln!(
                "warning: record carries an invite cap (private channel) but enc=false; \
                 the cap-derived pin wins (treating the channel as encrypted)"
            );
        }
        Some(String::from_utf8_lossy(&record.cap).into_owned())
    } else {
        if record.enc {
            return Err(AppError::Usage(
                "record claims enc=true but carries no invite cap; refusing to send into a \
                 believed-private channel without a cap — request a fresh pairing"
                    .to_owned(),
            ));
        }
        None
    };

    // 4. Daemon + join under the adder-set name (--as overrides, REQ-011).
    daemon_start().await?;
    let client = discover_live_client().await?;
    let handle = args.as_handle.clone().unwrap_or_else(|| record.agent_name.clone());
    let dialects: Vec<String> = record.dialects.iter().map(|d| d.name.clone()).collect();
    let response = client
        .create_agent(&CreateAgentRequest {
            dialects: dialects.clone(),
            auto_install_advertised: None,
            channel: Some(record.channel.clone()),
            handle: Some(handle.clone()),
            cap,
        })
        .await
        .map_err(map_local_api_request_error)?;

    for warning in &response.warnings {
        eprintln!("warning: {warning}");
    }
    let speaking = if response.dialects.is_empty() {
        "nothing".to_owned()
    } else {
        response.dialects.join(", ")
    };
    println!(
        "paired into {} as {} (added by {}) · speaking: {speaking}",
        record.channel, handle, record.adder
    );
    Ok(())
}

fn map_pair_error(error: crate::pairing::client::PairClientError) -> AppError {
    use crate::pairing::client::PairClientError;
    match error {
        PairClientError::BadHubUrl(_) | PairClientError::Pair(_) => {
            AppError::Usage(error.to_string())
        }
        PairClientError::HubError { .. } => AppError::Usage(error.to_string()),
        PairClientError::ConnectionFailed(_) | PairClientError::ClosedEarly => {
            AppError::RouterConnection
        }
        PairClientError::UnexpectedFrame { .. } | PairClientError::MalformedFrame(_) => {
            AppError::Internal(error.to_string())
        }
    }
}

/// The config `hark join` scaffolds: the chat hub URL is the only required
/// key — every other section has defaults.
fn build_chat_config_toml(hub_url: &str) -> String {
    format!(
        "# hark configuration — scaffolded by `hark join`.\n\
         # The ws_url PATH selects the transport: /chat/v1 -> chat hub,\n\
         # anything else -> router.\n\
         [router]\n\
         ws_url = \"{hub_url}\"\n"
    )
}

async fn init_command(args: InitArgs) -> AppResult<()> {
    validate_init_advertisement(&args.dialects)?;
    let client = discover_live_client().await.map_err(|error| {
        if matches!(error, AppError::DaemonNotRunning) {
            eprintln!("daemon_not_running: run `hark daemon start` first");
        }
        error
    })?;
    let response = client
        .create_agent(&CreateAgentRequest {
            dialects: args.dialects,
            // None → daemon-side default (true). The CLI does not expose a
            // knob for this; production agents always want their advertised
            // dialects R5-enforceable from the first message.
            auto_install_advertised: None,
            // Chat-hub fields; the daemon ignores them on the router transport.
            channel: args.channel,
            handle: args.handle,
            cap: args.cap,
        })
        .await
        .map_err(map_local_api_request_error)?;

    for warning in &response.warnings {
        eprintln!("warning: {warning}");
    }
    if args.json {
        println!(
            "{}",
            serde_json::to_string(&response).map_err(|error| AppError::Internal(format!(
                "failed to encode init JSON: {error}"
            )))?
        );
    } else {
        println!(
            "export CBCL_AGENT_HANDLE='{}'",
            shell_single_quote(&response.agent_handle)
        );
    }

    Ok(())
}

async fn recv_command(args: RecvArgs) -> AppResult<()> {
    let timeout_ms = match args.timeout {
        Some(timeout) => Some(parse_recv_timeout_ms(&timeout)?),
        None => None,
    };
    let client = discover_live_client().await?;
    let handle = resolve_session_handle(&client).await?;
    let response = client
        .recv(&handle, timeout_ms)
        .await
        .map_err(map_local_api_request_error)?;
    println!("{}", response.message);
    Ok(())
}

async fn close_command() -> AppResult<()> {
    let client = discover_live_client().await?;
    let handle = resolve_session_handle(&client).await?;
    client
        .close(&handle)
        .await
        .map_err(map_local_api_request_error)?;
    Ok(())
}

fn validate_init_advertisement(dialects: &[String]) -> AppResult<()> {
    if dialects.is_empty() {
        return Err(AppError::Usage(
            "at least one --dialect is required".to_owned(),
        ));
    }
    let mut seen = std::collections::HashSet::new();
    for dialect in dialects {
        validate_dialect_id(dialect).map_err(|error| AppError::Usage(error.to_string()))?;
        if !seen.insert(dialect) {
            return Err(AppError::Usage(format!("duplicate dialect: {dialect}")));
        }
    }

    Ok(())
}

async fn send_message_command(kind: SendMessageKind, args: MessageInputArgs) -> AppResult<()> {
    let message = read_message_input(args.message)?;
    // The CLI only sends reply/error/progress; emit is API-only (kind=emit).
    let expected_kind = kind
        .message_kind()
        .expect("CLI send commands use reply/error/progress");
    validate_for_send(&message, expected_kind).map_err(|error| {
        eprintln!("{}: {error}", error.code());
        AppError::CbclValidation
    })?;
    send_validated_message(kind, message).await
}

async fn progress_command(args: ProgressArgs) -> AppResult<()> {
    validate_dialect_id(&args.dialect).map_err(|error| AppError::Usage(error.to_string()))?;
    let message = build_progress_message(&args.thread, args.text.as_deref(), &args.dialect);
    validate_for_send(&message, MessageKind::Progress).map_err(|error| {
        eprintln!("{}: {error}", error.code());
        AppError::CbclValidation
    })?;
    send_validated_message(SendMessageKind::Progress, message).await
}

/// REQ-004 (SPEC-016): `hark emit` — the proactive plain-chat verb. Plain text
/// is wrapped into a valid CBCL `(tell @<channel> "<text>")` against the
/// agent's joined chat channel; an input that already looks like a CBCL form
/// (leading `(`) is validated and sent as-is. The wire frame is always valid
/// CBCL — there are no raw-text frames.
async fn emit_command(args: MessageInputArgs) -> AppResult<()> {
    let input = read_message_input(args.message)?;
    let input = input.trim();
    if input.is_empty() {
        return Err(AppError::Usage("emit requires a non-empty message".to_owned()));
    }

    let client = discover_live_client().await?;
    let handle = resolve_session_handle(&client).await?;

    let message = if emit_input_is_cbcl_form(input) {
        input.to_owned()
    } else {
        let channel = agent_chat_channel(&client, &handle).await?.ok_or_else(|| {
            AppError::Usage(
                "plain-text emit needs a chat-hub agent with a channel; \
                 on the router transport pass a full CBCL form instead"
                    .to_owned(),
            )
        })?;
        build_emit_message(input, &channel)
    };

    // Mirror reply/error/progress: validate locally before bothering the
    // daemon. An empty registry + fresh store is the lightweight context —
    // unknown dialects fall back to the base pipeline, exactly like the
    // daemon's fallback for not-yet-installed dialects.
    let registry = cbcl_core::dialect::DialectRegistry::default();
    let mut store = cbcl_core::store::ThreadedMessageStore::new();
    validate_for_emit(&message, &registry, &mut store).map_err(|error| {
        eprintln!("{}: {error}", error.code());
        AppError::CbclValidation
    })?;

    client
        .send(&handle, &SendRequest { kind: SendMessageKind::Emit, message })
        .await
        .map_err(map_local_api_request_error)?;
    Ok(())
}

/// The joined chat channel for `handle`, or `None` on the router transport.
async fn agent_chat_channel(
    client: &LocalApiClient,
    handle: &AgentHandle,
) -> AppResult<Option<String>> {
    let agents = client
        .agents()
        .await
        .map_err(|error| map_client_error(error, "daemon agents query failed"))?;
    let agent = agents
        .agents
        .into_iter()
        .find(|agent| agent.agent_handle == handle.as_str())
        .ok_or(AppError::AgentHandleUnavailable)?;
    Ok(agent.channel)
}

/// `true` when the emit input is already a CBCL form rather than plain text.
fn emit_input_is_cbcl_form(input: &str) -> bool {
    input.trim_start().starts_with('(')
}

fn build_emit_message(text: &str, channel: &str) -> String {
    format!("(tell {channel} \"{}\")", escape_cbcl_string(text))
}

async fn send_validated_message(kind: SendMessageKind, message: String) -> AppResult<()> {
    let client = discover_live_client().await?;
    let handle = resolve_session_handle(&client).await?;
    client
        .send(&handle, &SendRequest { kind, message })
        .await
        .map_err(map_local_api_request_error)?;
    Ok(())
}

async fn dialect_publish_command(args: DialectPublishArgs) -> AppResult<()> {
    let define = read_message_input(args.define)?;
    let define = define.trim().to_owned();
    let client = discover_live_client().await?;
    let handle = resolve_session_handle(&client).await?;
    let response = client
        .meta_publish(&handle, &MetaPublishRequest { define })
        .await
        .map_err(map_local_api_request_error)?;
    if args.json {
        let json = serde_json::json!({
            "digest": response.digest,
            "name": response.name,
        });
        println!("{json}");
    } else {
        println!("{} {}", response.digest, response.name);
    }
    Ok(())
}

async fn dialect_query_command(args: DialectQueryArgs) -> AppResult<()> {
    let client = discover_live_client().await?;
    let handle = resolve_session_handle(&client).await?;
    let response = client
        .meta_query(&handle, &MetaQueryRequest { name: args.name })
        .await
        .map_err(map_local_api_request_error)?;
    if args.json {
        let json = serde_json::json!({
            "digest": response.digest,
            "name": response.name,
            "define": response.define,
        });
        println!("{json}");
    } else {
        println!("{} {}", response.digest, response.name);
    }
    Ok(())
}

async fn dialect_list_command() -> AppResult<()> {
    let client = discover_live_client().await?;
    let handle = resolve_session_handle(&client).await?;
    let response = client
        .meta_list(&handle)
        .await
        .map_err(map_local_api_request_error)?;
    for name in &response.names {
        println!("{name}");
    }
    Ok(())
}

async fn dialect_subscribe_command(args: DialectSubscribeArgs) -> AppResult<()> {
    let client = discover_live_client().await?;
    let handle = resolve_session_handle(&client).await?;
    client
        .meta_subscribe(&handle, &MetaSubscribeRequest { pattern: args.pattern })
        .await
        .map_err(map_local_api_request_error)?;
    Ok(())
}

async fn dialect_unsubscribe_command() -> AppResult<()> {
    let client = discover_live_client().await?;
    let handle = resolve_session_handle(&client).await?;
    client
        .meta_unsubscribe(&handle)
        .await
        .map_err(map_local_api_request_error)?;
    Ok(())
}

fn read_message_input(message: Option<String>) -> AppResult<String> {
    if let Some(message) = message {
        return Ok(message);
    }

    let mut stdin = std::io::stdin();
    if stdin.is_terminal() {
        return Err(AppError::Usage(
            "message argument is required when stdin is a terminal".to_owned(),
        ));
    }

    let mut message = String::new();
    stdin
        .read_to_string(&mut message)
        .map_err(|error| AppError::Internal(format!("failed to read stdin: {error}")))?;
    Ok(message)
}

/// Resolve the agent handle for a session command (REQ-003, SPEC-016):
/// an explicit `CBCL_AGENT_HANDLE` always wins (multi-agent scripting);
/// otherwise fall back to the daemon-tracked active handle — no `eval`.
async fn resolve_session_handle(client: &LocalApiClient) -> AppResult<AgentHandle> {
    let env = std::env::var("CBCL_AGENT_HANDLE").ok();
    let active = if env.is_some() {
        None // don't bother the daemon; the env var decides
    } else {
        client
            .agents()
            .await
            .map_err(|error| map_client_error(error, "daemon agents query failed"))?
            .active_agent_handle
    };
    choose_agent_handle(env, active)
}

fn choose_agent_handle(
    env: Option<String>,
    active: Option<String>,
) -> AppResult<AgentHandle> {
    let value = env.or(active).ok_or(AppError::MissingAgentHandle)?;
    AgentHandle::new(value).map_err(|error| AppError::Usage(error.to_string()))
}

async fn discover_live_client() -> AppResult<LocalApiClient> {
    let paths = resolve_runtime_paths()
        .map_err(|error| AppError::Internal(format!("failed to resolve runtime dir: {error}")))?;
    let Some(record) = load_discovery_record(&paths)
        .map_err(|error| AppError::Internal(format!("failed to read daemon discovery: {error}")))?
    else {
        return Err(AppError::DaemonNotRunning);
    };

    ping_record(&record)
        .await
        .map_err(|error| map_client_error(error, "local daemon request failed"))
}

fn map_local_api_request_error(error: LocalApiRequestError) -> AppError {
    match error {
        LocalApiRequestError::AuthFailure => AppError::LocalAuth,
        LocalApiRequestError::Api(error, status) => {
            eprintln!("{}: {}", error.error.code, error.error.message);
            if let Some(hint) = &error.error.hint {
                eprintln!("hint: {hint}");
            }
            match error.error.code.as_str() {
                "malformed_agent_handle" => AppError::Usage(error.error.message),
                "unknown_agent_handle" | "agent_handle_unhealthy" | "recv_already_waiting" => {
                    AppError::AgentHandleUnavailable
                }
                "recv_timeout" | "meta_reply_timeout" => AppError::Timeout,
                "meta_send_busy" => AppError::AgentHandleUnavailable,
                "missing_router_ws_url"
                | "invalid_router_ws_url"
                | "router_auth_rejected"
                | "router_connection_failed"
                | "chat_connection_failed" => AppError::RouterConnection,
                "missing_chat_handle"
                | "chat_join_rejected"
                | "not_supported_on_chat_hub" => AppError::Usage(error.error.message),
                "chat_join_timeout" => AppError::Timeout,
                "chat_identity_unavailable" => AppError::Internal(error.error.message),
                "missing_dialect"
                | "duplicate_dialect"
                | "invalid_dialect"
                | "undeclared_dialect"
                | "invalid_subscribe_pattern"
                | "dialect_unknown_to_router" => AppError::Usage(error.error.message),
                "cbcl_validation_failed"
                | "message_kind_mismatch"
                | "missing_thread"
                | "duplicate_thread"
                | "invalid_thread"
                | "shape_violation"
                | "causal_violation" => AppError::CbclValidation,
                "meta_reply_malformed"
                | "meta_reply_missing_digest"
                | "meta_reply_missing_name" => {
                    AppError::Internal(error.error.message)
                }
                "daemon_stopping" => AppError::Internal(error.error.message),
                _ if status == reqwest::StatusCode::SERVICE_UNAVAILABLE => {
                    AppError::RouterConnection
                }
                _ => AppError::Internal(error.error.message),
            }
        }
        LocalApiRequestError::RequestFailed(error) => {
            AppError::Internal(format!("local daemon request failed: {error}"))
        }
        LocalApiRequestError::DecodeFailed(error) => {
            AppError::Internal(format!("failed to decode local API response: {error}"))
        }
    }
}

fn build_progress_message(thread: &str, text: Option<&str>, dialect: &str) -> String {
    let mut message = format!(
        "(lang {} (tell @router \"progress\" :thread \"{}\"",
        dialect,
        escape_cbcl_string(thread)
    );
    if let Some(text) = text {
        message.push_str(&format!(" :text \"{}\"", escape_cbcl_string(text)));
    }
    message.push_str("))");
    message
}

fn escape_cbcl_string(value: &str) -> String {
    value
        .chars()
        .flat_map(|character| match character {
            '\\' => "\\\\".chars().collect::<Vec<_>>(),
            '"' => "\\\"".chars().collect::<Vec<_>>(),
            '\n' => "\\n".chars().collect::<Vec<_>>(),
            '\r' => "\\r".chars().collect::<Vec<_>>(),
            '\t' => "\\t".chars().collect::<Vec<_>>(),
            _ => vec![character],
        })
        .collect()
}

fn parse_recv_timeout_ms(input: &str) -> AppResult<u64> {
    let (number, multiplier) = if let Some(number) = input.strip_suffix("ms") {
        (number, 1_u64)
    } else if let Some(number) = input.strip_suffix('s') {
        (number, 1_000_u64)
    } else if let Some(number) = input.strip_suffix('m') {
        (number, 60_000_u64)
    } else if let Some(number) = input.strip_suffix('h') {
        (number, 3_600_000_u64)
    } else {
        return Err(AppError::Usage(
            "timeout must use ms, s, m, or h suffix".to_owned(),
        ));
    };

    let value = number
        .parse::<u64>()
        .map_err(|_| AppError::Usage("timeout value must be a positive integer".to_owned()))?;
    if value == 0 {
        return Err(AppError::Usage("timeout must be positive".to_owned()));
    }
    let millis = value
        .checked_mul(multiplier)
        .ok_or_else(|| AppError::Usage("timeout is too large".to_owned()))?;
    if millis > MAX_RECV_TIMEOUT_MS {
        return Err(AppError::Usage("timeout exceeds maximum 2160h".to_owned()));
    }
    Ok(millis)
}

fn shell_single_quote(value: &str) -> String {
    value.replace('\'', "'\\''")
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
    let result = serve_local_api_with_agents(
        listener,
        record,
        Some(paths.discovery_file.clone()),
        agents,
        config,
    )
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
            if let Some(active) = &agents.active_agent_handle {
                println!("active: {active}");
            }
            for agent in agents.agents {
                let dialects = agent.dialects.join(",");
                println!(
                    "{} {} router_agent_id={} dialects=[{}] queued_messages={} queued_bytes={}",
                    agent.agent_handle,
                    agent.state,
                    agent.router_agent_id,
                    dialects,
                    agent.queued_messages,
                    agent.queued_bytes
                );
                if let Some(reason) = agent.unhealthy_reason {
                    println!("  unhealthy_reason={reason}");
                }
                if let Some(detail) = agent.unhealthy_detail {
                    println!("  unhealthy_detail={detail}");
                }
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

    use super::{
        Cli, Command, ConfigCommand, DaemonCommand, build_chat_config_toml, build_emit_message,
        build_progress_message, choose_agent_handle, emit_input_is_cbcl_form, escape_cbcl_string,
        parse_recv_timeout_ms, validate_init_advertisement,
    };

    #[test]
    fn command_tree_matches_mvp_surface() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_daemon_subcommands() {
        let cli = Cli::parse_from(["hark", "daemon", "run"]);
        assert!(matches!(cli.command, Command::Daemon(DaemonCommand::Run)));

        let cli = Cli::parse_from(["hark", "daemon", "start"]);
        assert!(matches!(cli.command, Command::Daemon(DaemonCommand::Start)));
    }

    #[test]
    fn parses_config_subcommands() {
        let cli = Cli::parse_from(["hark", "config", "path"]);
        assert!(matches!(cli.command, Command::Config(ConfigCommand::Path)));

        let cli = Cli::parse_from(["hark", "config", "show-example"]);
        assert!(matches!(
            cli.command,
            Command::Config(ConfigCommand::ShowExample)
        ));

        let cli = Cli::parse_from(["hark", "config", "init"]);
        assert!(matches!(cli.command, Command::Config(ConfigCommand::Init)));
    }

    #[test]
    fn parses_init_arguments() {
        let cli = Cli::parse_from([
            "hark",
            "init",
            "--dialect",
            "elf",
            "--dialect",
            "arena-v1",
            "--json",
        ]);

        let Command::Init(args) = cli.command else {
            panic!("expected init command");
        };

        assert_eq!(args.dialects, ["elf", "arena-v1"]);
        assert!(args.json);
    }

    #[test]
    fn rejects_init_without_dialect() {
        let error = Cli::try_parse_from(["hark", "init"]).unwrap_err();
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn parses_agent_workflow_commands() {
        let cli = Cli::parse_from(["hark", "recv", "--timeout", "30s"]);
        let Command::Recv(args) = cli.command else {
            panic!("expected recv command");
        };
        assert_eq!(args.timeout.as_deref(), Some("30s"));

        let cli = Cli::parse_from(["hark", "reply", "(reply @router \"ok\")"]);
        assert!(matches!(cli.command, Command::Reply(_)));

        let cli = Cli::parse_from([
            "hark",
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

        let cli = Cli::parse_from(["hark", "close"]);
        assert!(matches!(cli.command, Command::Close));
    }

    #[test]
    fn parses_join_arguments() {
        let cli = Cli::parse_from([
            "hark", "join", "@research", "--as", "@aria", "--speak", "cite,vote",
        ]);
        let Command::Join(args) = cli.command else {
            panic!("expected join command");
        };
        assert_eq!(args.channel, "@research");
        assert_eq!(args.as_handle, "@aria");
        assert_eq!(args.speak, ["cite", "vote"]);
        assert_eq!(args.cap, None);
        assert_eq!(args.hub, None);

        // Omitting --speak advertises nothing (HP-2).
        let cli = Cli::parse_from(["hark", "join", "@demo", "--as", "@aria"]);
        let Command::Join(args) = cli.command else {
            panic!("expected join command");
        };
        assert!(args.speak.is_empty());
    }

    #[test]
    fn parses_pair_arguments() {
        let cli = Cli::parse_from(["hark", "pair", "42-account-clinic-text-wheel"]);
        let Command::Pair(args) = cli.command else {
            panic!("expected pair command");
        };
        assert_eq!(args.code, "42-account-clinic-text-wheel");
        assert_eq!(args.as_handle, None);
        assert_eq!(args.hub, None);

        let cli = Cli::parse_from([
            "hark", "pair", "code", "--as", "@bot", "--hub", "wss://h/chat/v1",
        ]);
        let Command::Pair(args) = cli.command else {
            panic!("expected pair command");
        };
        assert_eq!(args.as_handle.as_deref(), Some("@bot"));
        assert_eq!(args.hub.as_deref(), Some("wss://h/chat/v1"));
    }

    #[test]
    fn builds_chat_scaffold_config() {
        let toml = build_chat_config_toml("wss://hub.example/chat/v1");
        let dir = tempfile::tempdir().expect("tempdir should be created");
        let path = dir.path().join("config.toml");
        std::fs::write(&path, &toml).expect("scaffold should be written");
        // File-only load: env overrides would race other tests' env vars.
        let config = crate::config::load_file_backed_config(Some(path))
            .expect("scaffold config should parse");
        assert_eq!(
            config.router.ws_url.as_deref(),
            Some("wss://hub.example/chat/v1")
        );
        assert_eq!(
            config.transport().expect("transport should resolve"),
            crate::config::Transport::Chat
        );
    }

    #[test]
    fn chooses_env_handle_over_daemon_active_handle() {
        let env_handle = crate::daemon::AgentHandle::generate();
        let active_handle = crate::daemon::AgentHandle::generate();

        // An explicit env var always wins (multi-agent scripting).
        let chosen = choose_agent_handle(
            Some(env_handle.as_str().to_owned()),
            Some(active_handle.as_str().to_owned()),
        )
        .expect("env handle should resolve");
        assert_eq!(chosen.as_str(), env_handle.as_str());

        // Without the env var the daemon-tracked active handle is used.
        let chosen = choose_agent_handle(None, Some(active_handle.as_str().to_owned()))
            .expect("active handle should resolve");
        assert_eq!(chosen.as_str(), active_handle.as_str());

        // Neither → the missing-handle error.
        assert!(choose_agent_handle(None, None).is_err());
    }

    #[test]
    fn parses_emit_arguments() {
        let cli = Cli::parse_from(["hark", "emit", "looking into it"]);
        let Command::Emit(args) = cli.command else {
            panic!("expected emit command");
        };
        assert_eq!(args.message.as_deref(), Some("looking into it"));
    }

    #[test]
    fn wraps_plain_text_emit_into_tell() {
        assert_eq!(
            build_emit_message("looking into it", "@research"),
            r#"(tell @research "looking into it")"#
        );
        assert_eq!(
            build_emit_message("say \"hi\"\nnow", "@general"),
            r#"(tell @general "say \"hi\"\nnow")"#
        );
    }

    #[test]
    fn detects_full_cbcl_emit_input() {
        assert!(emit_input_is_cbcl_form(r#"(tell @a "x")"#));
        assert!(emit_input_is_cbcl_form(
            "  (lang elf (ask @router \"work\" :thread \"rcp-9\"))  "
        ));
        assert!(!emit_input_is_cbcl_form("hello world"));
        assert!(!emit_input_is_cbcl_form(""));
    }

    #[test]
    fn builds_progress_message_with_escaped_values() {
        assert_eq!(
            build_progress_message("rcp-1", None, "elf"),
            r#"(lang elf (tell @router "progress" :thread "rcp-1"))"#
        );
        assert_eq!(
            build_progress_message("rcp\"2", Some("line\nnext"), "elf"),
            r#"(lang elf (tell @router "progress" :thread "rcp\"2" :text "line\nnext"))"#
        );
    }

    #[test]
    fn escapes_cbcl_strings() {
        assert_eq!(escape_cbcl_string("a\\b\"c\n"), "a\\\\b\\\"c\\n");
    }

    #[test]
    fn parses_recv_timeout_units() {
        assert_eq!(parse_recv_timeout_ms("1ms").unwrap(), 1);
        assert_eq!(parse_recv_timeout_ms("2s").unwrap(), 2_000);
        assert_eq!(parse_recv_timeout_ms("3m").unwrap(), 180_000);
        assert_eq!(parse_recv_timeout_ms("4h").unwrap(), 14_400_000);
        assert_eq!(parse_recv_timeout_ms("2160h").unwrap(), 7_776_000_000);

        assert!(parse_recv_timeout_ms("0s").is_err());
        assert!(parse_recv_timeout_ms("2161h").is_err());
        assert!(parse_recv_timeout_ms("10").is_err());
    }

    #[test]
    fn validates_duplicate_init_values_before_api_call() {
        // missing dialect → reject
        assert!(validate_init_advertisement(&[]).is_err());
        // duplicate dialect → reject
        assert!(
            validate_init_advertisement(&["elf".to_owned(), "elf".to_owned()]).is_err()
        );
    }
}
