use cbcl_router_client::{cli, errors::ExitCode};
use clap::Parser;

#[tokio::main]
async fn main() {
    let cli = cli::Cli::parse();

    if let Err(error) = cli::run(cli).await {
        eprintln!("error: {error}");
        std::process::exit(error.exit_code().as_i32());
    }

    std::process::exit(ExitCode::Success.as_i32());
}
