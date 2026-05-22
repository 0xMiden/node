// This is required due to a long chain of and_then in BlockBuilder::build_block causing rust error
// E0275.
#![recursion_limit = "256"]

use conf::{Conf, Subcommands};

mod commands;
#[cfg(test)]
mod tests;

// COMMANDS
// ================================================================================================

#[derive(Conf, Debug)]
#[conf(version)]
struct Cli {
    #[conf(subcommands)]
    command: Command,
}

#[derive(Subcommands, Debug)]
enum Command {
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
    let command = Cli::parse().command;

    // Configure tracing with optional OpenTelemetry exporting support.
    let _otel_guard = miden_node_utils::logging::setup_tracing(command.open_telemetry())?;

    command.execute().await
}
