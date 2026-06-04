use clap::Parser;
mod commands;

// MAIN
// ================================================================================================

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let command = commands::ValidatorCommand::parse();

    let _otel_guard = miden_node_utils::logging::setup_tracing(command.open_telemetry())?;

    command.handle().await
}
