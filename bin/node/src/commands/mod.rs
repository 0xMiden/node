mod block_producer;
mod lifecycle;
mod modes;
mod rpc;
mod runtime;
pub(crate) mod section;
mod store;

use clap::Subcommand;
pub use lifecycle::{BootstrapCommand, MigrateCommand};
use miden_node_utils::logging::OpenTelemetry;
pub use modes::{FullNodeCommand, SequencerCommand};

const ENV_DATA_DIRECTORY: &str = "MIDEN_NODE_DATA_DIRECTORY";

#[derive(Subcommand, Debug)]
#[expect(clippy::large_enum_variant, reason = "cli is a once-off usage")]
pub enum Command {
    /// Start the node in sequencer mode.
    ///
    /// Each network has exactly one sequencer, operated by that network's operator. All other
    /// nodes for the network must use `full` mode.
    ///
    /// Use `full` mode to run a non-sequencing node that syncs blocks from an upstream source.
    Sequencer(SequencerCommand),

    /// Start the node in full-node mode.
    ///
    /// In this mode, the node syncs blocks from an upstream source and serves a local RPC API.
    /// This is useful for avoiding rate limits on official networks, or for horizontally scaling
    /// RPC traffic.
    Full(FullNodeCommand),

    /// Initialize the node's storage from a trusted genesis block.
    ///
    /// Performs one-time initialization of an empty node data directory from a trusted, signed
    /// genesis block. The data directory contains the node's local data storage and must be
    /// initialized before the node can be started.
    Bootstrap(BootstrapCommand),

    /// Apply pending migrations to the node's storage.
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
    pub(crate) fn open_telemetry(&self) -> OpenTelemetry {
        match self {
            Command::Sequencer(_) => OpenTelemetry::from_env()
                .with_name("node")
                .with_attribute("miden.node.role", "sequencer"),
            Command::Full(_) => OpenTelemetry::from_env()
                .with_name("node")
                .with_attribute("miden.node.role", "full"),
            Command::Bootstrap(_) | Command::Migrate(_) => OpenTelemetry::Disabled,
        }
    }

    pub(crate) async fn execute(self) -> anyhow::Result<()> {
        match self {
            Command::Bootstrap(bootstrap_command) => bootstrap_command.handle().await,
            Command::Migrate(migrate_command) => migrate_command.handle().await,
            Command::Sequencer(sequencer_command) => sequencer_command.handle().await,
            Command::Full(full_node_command) => full_node_command.handle().await,
        }
    }
}
