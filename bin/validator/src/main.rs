use clap::Parser;
use miden_node_utils::logging::OpenTelemetry;

mod commands;

// MAIN
// ================================================================================================

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let command = commands::ValidatorCommand::parse();

    let otel = if command.is_open_telemetry_enabled() {
        OpenTelemetry::enabled().with_name("validator")
    } else {
        OpenTelemetry::Disabled
    };

    let _otel_guard = miden_node_utils::logging::setup_tracing(otel)?;

    command.handle().await
}
