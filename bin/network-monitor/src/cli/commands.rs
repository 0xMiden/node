//! CLI command definitions.

use clap::{Parser, Subcommand};

use crate::commands::start_monitor;
use crate::config::MonitorConfig;

/// Main CLI structure.
#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// Available commands.
#[derive(Subcommand)]
pub enum Command {
    /// Starts the network monitor
    Start(MonitorConfig),
}

impl Cli {
    /// Execute the parsed command.
    pub async fn execute(self) -> anyhow::Result<()> {
        match self.command {
            Command::Start(config) => Box::pin(start_monitor(config)).await,
        }
    }
}
