// This is required due to a long chain of and_then in BlockBuilder::build_block causing rust error
// E0275.
#![recursion_limit = "256"]

use clap::Parser;
use clap::error::ErrorKind;
use commands::Command;

mod commands;

const LOG_TARGET: &str = "user::miden-node";

// COMMANDS
// ================================================================================================

/// Operate and maintain a Miden node.
#[derive(Parser, Debug)]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

// MAIN
// ================================================================================================

fn parse_cli() -> Cli {
    match Cli::try_parse() {
        Ok(cli) => cli,
        // We inject custom section descriptions into help output to improve readability.
        Err(err) if err.kind() == ErrorKind::DisplayHelp => {
            print!("{}", commands::section::inject_section_descriptions(err.to_string()));
            std::process::exit(err.exit_code());
        },
        Err(err) => err.exit(),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = parse_cli();

    // Configure tracing with optional OpenTelemetry exporting support.
    let _otel_guard = miden_node_utils::logging::setup_tracing(cli.command.open_telemetry())?;

    miden_node_utils::shutdown::run_with_shutdown(|shutdown| cli.command.execute(shutdown)).await
}
