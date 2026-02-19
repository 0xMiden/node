//! Miden Network Monitor
//!
//! A monitor application for Miden network infrastructure that provides real-time status
//! monitoring and account deployment capabilities.

use anyhow::Result;
use clap::Parser;

// Module declarations
mod cli;
pub mod commands;
pub mod config;
pub mod counter;
mod deploy;
pub mod explorer;
pub mod faucet;
pub mod frontend;
mod monitor;
pub mod note_transport;
pub mod remote_prover;
pub mod status;

// Re-exports for cleaner imports
use cli::Cli;
// Re-export for other modules
pub use monitor::tasks::current_unix_timestamp_secs;

/// Component identifier for structured logging and tracing
pub const COMPONENT: &str = "miden-network-monitor";

/// Network Monitor main function.
///
/// This function parses command-line arguments and delegates to the appropriate
/// command handler. The monitor supports two main commands:
/// - `start`: Runs the network monitoring service with web dashboard
/// - `deploy-account`: Creates and deploys Miden accounts to the network
#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    cli.execute().await
}
