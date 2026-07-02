//! Miden Network Monitor
//!
//! A monitor application for Miden network infrastructure that provides real-time status
//! monitoring across the RPC, provers, faucet, explorer, and network transaction services.

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
pub mod service;
pub mod service_status;
pub mod status;
pub mod validator;
mod view;

// Re-exports for cleaner imports
use cli::Cli;
// Re-export for other modules
pub use service_status::current_unix_timestamp_secs;

/// Component identifier for structured logging and tracing
pub const COMPONENT: &str = "miden-network-monitor";

/// Tracing target used for user-visible log messages.
pub const LOG_TARGET: &str = "user::miden-network-monitor";

/// Network Monitor main function.
///
/// Parses command-line arguments and runs the `start` subcommand, which launches the network
/// monitoring service with its web dashboard.
#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    Box::pin(cli.execute()).await
}
