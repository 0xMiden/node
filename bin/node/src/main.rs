// This is required due to a long chain of and_then in BlockBuilder::build_block causing rust error
// E0275.
#![recursion_limit = "256"]

use clap::{Parser, Subcommand};
use miden_node_utils::logging::OpenTelemetry;

mod commands;

// COMMANDS
// ================================================================================================

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Commands related to the node's store component.
    #[command(subcommand)]
    Store(commands::store::StoreCommand),

    /// Commands related to the node's RPC component.
    #[command(subcommand)]
    Rpc(commands::rpc::RpcCommand),

    /// Commands related to the node's block-producer component.
    #[command(subcommand)]
    BlockProducer(commands::block_producer::BlockProducerCommand),

    // Commands related to the node's validator component.
    #[command(subcommand)]
    Validator(commands::validator::ValidatorCommand),

    /// Commands relevant to running all components in the same process.
    ///
    /// This is the recommended way to run the node at the moment.
    #[command(subcommand)]
    Bundled(commands::bundled::BundledCommand),
}

impl Command {
    /// Whether OpenTelemetry tracing exporter should be enabled.
    ///
    /// This is enabled for some subcommands if the `--open-telemetry` flag is specified.
    fn open_telemetry(&self) -> OpenTelemetry {
        if match self {
            Command::Store(subcommand) => subcommand.is_open_telemetry_enabled(),
            Command::Rpc(subcommand) => subcommand.is_open_telemetry_enabled(),
            Command::BlockProducer(subcommand) => subcommand.is_open_telemetry_enabled(),
            Command::Validator(subcommand) => subcommand.is_open_telemetry_enabled(),
            Command::Bundled(subcommand) => subcommand.is_open_telemetry_enabled(),
        } {
            OpenTelemetry::Enabled
        } else {
            OpenTelemetry::Disabled
        }
    }

    async fn execute(self) -> anyhow::Result<()> {
        match self {
            Command::Rpc(rpc_command) => rpc_command.handle().await,
            Command::Store(store_command) => store_command.handle().await,
            Command::BlockProducer(block_producer_command) => block_producer_command.handle().await,
            Command::Validator(validator) => validator.handle().await,
            Command::Bundled(node) => node.handle().await,
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
