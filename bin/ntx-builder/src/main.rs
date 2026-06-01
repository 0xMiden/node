use clap::Parser;
mod commands;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let command = commands::NtxBuilderCommand::parse();

    let _otel_guard = miden_node_utils::logging::setup_tracing(command.open_telemetry())?;

    command.handle().await
}
