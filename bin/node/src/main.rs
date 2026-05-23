// This is required due to a long chain of and_then in BlockBuilder::build_block causing rust error
// E0275.
#![recursion_limit = "256"]

use clap::{Parser, Subcommand};

mod commands;
#[cfg(test)]
mod tests;

// COMMANDS
// ================================================================================================

/// Operate and maintain a Miden node.
///
/// Sync to an existing network by running the node in RPC mode, or in sequencer mode to operate a
/// local dev network.
///
/// A node must first be initialized using `bootstrap` and occasionally maintained after updates by
/// running `migrate`.
#[derive(Parser, Debug)]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Initialize a node from a signed genesis block.
    ///
    /// Performs one-time initialization of an empty node data directory from a trusted, signed
    /// genesis block. This is required before the node can be started.
    Bootstrap(commands::BootstrapCommand),

    /// Apply pending database migrations.
    ///
    /// Applies any migrations required by the node database in an existing data directory. Use this
    /// after upgrading to a release that changes the database schema.
    ///
    /// Cannot be run on an empty data directory; use `bootstrap` first.
    Migrate(commands::MigrateCommand),

    /// Run a node in sequencer mode.
    ///
    /// Runs a sequencer node which maintains a mempool of submitted transactions and produces
    /// blocks. Miden is currently centralized and only one of these exists per network.
    ///
    /// Note that the node still exposes an RPC API in this mode and can be used for local dev
    /// purposes.
    ///
    /// Run the node in RPC mode to sync blocks from an existing network and avoid rate-limiting.
    Sequencer(commands::SequencerCommand),

    /// Run a node in RPC mode.
    ///
    /// In this mode, the node syncs blocks from an upstream RPC source and is useful for providing
    /// a local RPC API to avoid rate-limiting on official networks.
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
