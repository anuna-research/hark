use clap::Parser;
use hark::{cli, errors::ExitCode};
use tracing_subscriber::{EnvFilter, fmt};

#[tokio::main]
async fn main() {
    // Initialise tracing once per process. Logs go to stderr so daemon
    // foreground (`daemon run`) and short CLI invocations both surface
    // warn-level events such as inbound R5 violations (`target =
    // hark::r5`). Filter defaults to `info`; override with `RUST_LOG`.
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();

    let cli = cli::Cli::parse();

    if let Err(error) = cli::run(cli).await {
        eprintln!("error: {error}");
        std::process::exit(error.exit_code().as_i32());
    }

    std::process::exit(ExitCode::Success.as_i32());
}
