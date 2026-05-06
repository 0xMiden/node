use clap::Parser;
use miden_node_utils::logging::OpenTelemetry;

mod commands;

// CLI
// ================================================================================================

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: commands::ValidatorCommand,
}

impl Cli {
    fn open_telemetry(&self) -> OpenTelemetry {
        if self.command.is_open_telemetry_enabled() {
            OpenTelemetry::Enabled
        } else {
            OpenTelemetry::Disabled
        }
    }
}

// MAIN
// ================================================================================================

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let _otel_guard = miden_node_utils::logging::setup_tracing(cli.open_telemetry())?;

    cli.command.handle().await
}
