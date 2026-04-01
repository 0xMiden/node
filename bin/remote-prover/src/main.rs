use anyhow::Context;
use clap::Parser;
use miden_node_utils::logging::{OpenTelemetry, setup_tracing};
use tracing::info;

mod generated;
mod server;

const COMPONENT: &str = "miden-prover";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _otel_guard = setup_tracing(OpenTelemetry::Enabled)?;
    info!(target: COMPONENT, "Tracing initialized");

    let (handle, _port) =
        server::Server::parse().spawn().await.context("failed to spawn server")?;

    handle.await.context("proof server panicked").flatten()
}
