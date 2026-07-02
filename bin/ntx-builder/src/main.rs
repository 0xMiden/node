use clap::Parser;
mod commands;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let command = commands::NtxBuilderCommand::parse();

    let _otel_guard = miden_node_utils::logging::setup_tracing(command.open_telemetry())?;

    miden_node_utils::shutdown::run_with_shutdown(|shutdown| command.handle(shutdown)).await
}
