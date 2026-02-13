use std::num::NonZeroUsize;

use clap::Parser;
use miden_node_utils::logging::{OpenTelemetry, setup_tracing};
use miden_remote_prover::COMPONENT;
use miden_remote_prover::api::ProofType;
use tracing::info;

pub(crate) mod commands;
pub(crate) mod proxy;
pub(crate) mod utils;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _otel_guard = setup_tracing(OpenTelemetry::Enabled)?;
    info!(target: COMPONENT, "Tracing initialized");

    let cli = CliConfig::parse();

    let cli = commands::worker::StartWorker {
        localhost: false,
        port: cli.port,
        proof_type: cli.kind,
        timeout: cli.timeout,
    };

    // execute cli action
    cli.execute().await
}

#[derive(clap::Parser)]
struct CliConfig {
    /// The port the gRPC server will be hosted on.
    #[arg(long, default_value = "50051", env = "MIDEN_PROVER_PORT")]
    port: u16,
    /// The proof type that the prover will be handling.
    #[arg(long, env = "MIDEN_PROVER_KIND")]
    kind: ProofType,
    /// Maximum time allowed for a proof request to complete. Once exceeded, the request is
    /// aborted.
    #[arg(long, default_value = "60s", env = "MIDEN_PROVER_TIMEOUT", value_parser = humantime::parse_duration)]
    timeout: std::time::Duration,
    /// Maximum number of concurrent proof requests that the prover will allow.
    ///
    /// Note that the prover only proves one request at a time; the rest are queued. This capacity
    /// is used to limit the number of requests that can be queued at any given time, and includes
    /// the one request that is currently being processed.
    #[arg(long, default_value_t = NonZeroUsize::new(1).unwrap(), env = "MIDEN_PROVER_CAPACITY")]
    capacity: NonZeroUsize,
}
