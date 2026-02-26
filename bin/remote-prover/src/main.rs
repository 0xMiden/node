use anyhow::Context;
use clap::Parser;
use miden_node_utils::logging::{OpenTelemetry, setup_tracing};
use miden_remote_prover::COMPONENT;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _otel_guard = setup_tracing(OpenTelemetry::Enabled)?;
    info!(target: COMPONENT, "Tracing initialized");

    let (handle, _port) = miden_remote_prover::server::Server::parse()
        .spawn()
        .await
        .context("failed to spawn server")?;

    handle.await.context("proof server panicked").flatten()
}
