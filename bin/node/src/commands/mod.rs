mod block_producer;
mod lifecycle;
mod modes;
mod rpc;
mod runtime;
pub(crate) mod section;
mod store;

use clap::Subcommand;
pub use lifecycle::{BootstrapCommand, MigrateCommand};
pub use modes::{RpcCommand, SequencerCommand};

const ENV_DATA_DIRECTORY: &str = "MIDEN_NODE_DATA_DIRECTORY";

#[derive(Subcommand, Debug)]
#[expect(clippy::large_enum_variant, reason = "cli is a once-off usage")]
pub enum Command {
    /// Run a node in sequencer mode.
    ///
    /// Each network has exactly one sequencer, and this therefore cannot be used for official
    /// networks. Use this mode to run your own local network for dev purposes.
    ///
    /// Use `rpc` mode to run a non-sequencing node that syncs blocks from an upstream RPC source.
    Sequencer(SequencerCommand),

    /// Run a node in RPC mode.
    ///
    /// In this mode, the node syncs blocks from an upstream RPC source and is useful for
    /// providing a local RPC API to avoid rate-limiting on official networks, or for
    /// horizontally scaling RPC traffic.
    Rpc(RpcCommand),

    /// Initialize a node from a signed genesis block.
    ///
    /// Performs one-time initialization of an empty node data directory from a trusted, signed
    /// genesis block. The data directory contains the node's local data storage and must be
    /// initialized before the node can be started.
    Bootstrap(BootstrapCommand),

    /// Apply pending node data migrations.
    ///
    /// Migrates the node's data storage from its current schema version to the version required by
    /// this binary. This is a no-op if the data directory is already at the latest version.
    ///
    /// Backwards migrations are not supported. If the data directory is older than the minimum
    /// supported version, run an older node binary first and migrate forward in stages until this
    /// binary can complete the migration.
    ///
    /// Cannot be run on an empty data directory; use `bootstrap` first.
    Migrate(MigrateCommand),
}

impl Command {
    pub(crate) fn open_telemetry(&self) -> miden_node_utils::logging::OpenTelemetry {
        match self {
            Command::Sequencer(command) => command.runtime.open_telemetry(),
            Command::Rpc(command) => command.runtime.open_telemetry(),
            Command::Bootstrap(_) | Command::Migrate(_) => {
                miden_node_utils::logging::OpenTelemetry::Disabled
            },
        }
    }

    pub(crate) async fn execute(self) -> anyhow::Result<()> {
        match self {
            Command::Bootstrap(bootstrap_command) => bootstrap_command.handle(),
            Command::Migrate(migrate_command) => migrate_command.handle().await,
            Command::Sequencer(sequencer_command) => sequencer_command.handle(),
            Command::Rpc(rpc_command) => rpc_command.handle(),
        }
    }
}
