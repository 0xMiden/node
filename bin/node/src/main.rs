// This is required due to a long chain of and_then in BlockBuilder::build_block causing rust error
// E0275.
#![recursion_limit = "256"]

use clap::{Parser, Subcommand};

mod commands;
#[cfg(test)]
mod tests;

// COMMANDS
// ================================================================================================

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Bootstraps the node store from a pre-signed genesis block.
    Bootstrap(commands::BootstrapCommand),

    /// Applies pending store database migrations.
    Migrate(commands::MigrateCommand),

    /// Runs a complete node which produces blocks in-process.
    Sequencer(commands::SequencerCommand),

    /// Runs a complete node which syncs blocks from a block stream source.
    Rpc(commands::RpcCommand),
}

impl Command {
    fn open_telemetry(&self) -> miden_node_utils::logging::OpenTelemetry {
        match self {
            Command::Sequencer(command) => command.runtime.open_telemetry(),
            Command::Rpc(command) => command.runtime.open_telemetry(),
            Command::Bootstrap(_) | Command::Migrate(_) => {
                miden_node_utils::logging::OpenTelemetry::Disabled
            },
        }
    }

    async fn execute(self) -> anyhow::Result<()> {
        match self {
            Command::Bootstrap(bootstrap_command) => bootstrap_command.handle(),
            Command::Migrate(migrate_command) => migrate_command.handle().await,
            Command::Sequencer(sequencer_command) => sequencer_command.handle(),
            Command::Rpc(rpc_command) => rpc_command.handle(),
        }
    }
}

// MAIN
// ================================================================================================

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Configure tracing with optional OpenTelemetry exporting support.
    let _otel_guard = miden_node_utils::logging::setup_tracing(cli.command.open_telemetry())?;

    cli.command.execute().await
}
