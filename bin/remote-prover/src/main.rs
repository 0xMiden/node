use anyhow::Context;
use clap::Parser;
use tracing::info;

mod server;

const COMPONENT: &str = "miden-prover";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let server = server::Server::parse();

    let _otel_guard = miden_node_utils::logging::setup_tracing(server.open_telemetry())?;
    info!(target: COMPONENT, "Tracing initialized");

    let (handle, _port) = server.spawn().await.context("failed to spawn server")?;

    handle.await.context("proof server panicked").flatten()
}
