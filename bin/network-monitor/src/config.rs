//! Network monitor configuration.
//!
//! This module contains the configuration structures and constants for the network monitor.
//! Configuration for the monitor.

use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use url::Url;

// MONITOR CONFIGURATION CONSTANTS
// ================================================================================================

const DEFAULT_RPC_URL: &str = "http://0.0.0.0:57291";
const DEFAULT_PORT: u16 = 3000;

/// Configuration for the monitor.
///
/// This struct contains the configuration for the monitor.
#[derive(Debug, Clone, Parser)]
pub struct MonitorConfig {
    /// The URL of the RPC service.
    #[arg(
        long = "rpc-url",
        env = "MIDEN_MONITOR_RPC_URL",
        default_value = DEFAULT_RPC_URL,
        help = "The URL of the RPC service"
    )]
    pub rpc_url: Url,

    /// The URLs of the remote provers for status checking (comma-separated).
    #[arg(
        long = "remote-prover-urls",
        env = "MIDEN_MONITOR_REMOTE_PROVER_URLS",
        value_delimiter = ',',
        help = "The URLs of the remote provers for status checking (comma-separated)"
    )]
    pub remote_prover_urls: Vec<Url>,

    /// The URL of the faucet service for testing (optional).
    #[arg(
        long = "faucet-url",
        env = "MIDEN_MONITOR_FAUCET_URL",
        help = "The URL of the faucet service for testing (optional)"
    )]
    pub faucet_url: Option<Url>,

    /// The interval at which to test the remote provers services.
    #[arg(
        long = "remote-prover-test-interval",
        env = "MIDEN_MONITOR_REMOTE_PROVER_TEST_INTERVAL",
        default_value = "2m",
        value_parser = humantime::parse_duration,
        help = "The interval at which to test the remote provers services"
    )]
    pub remote_prover_test_interval: Duration,

    /// The interval at which to test the faucet services.
    #[arg(
        long = "faucet-test-interval",
        env = "MIDEN_MONITOR_FAUCET_TEST_INTERVAL",
        default_value = "2m",
        value_parser = humantime::parse_duration,
        help = "The interval at which to test the faucet services"
    )]
    pub faucet_test_interval: Duration,

    /// The interval at which to check the status of the services.
    #[arg(
        long = "status-check-interval",
        env = "MIDEN_MONITOR_STATUS_CHECK_INTERVAL",
        default_value = "3s",
        value_parser = humantime::parse_duration,
        help = "The interval at which to check the status of the services"
    )]
    pub status_check_interval: Duration,

    /// The port of the monitor.
    #[arg(
        long = "port",
        short = 'p',
        env = "MIDEN_MONITOR_PORT",
        default_value_t = DEFAULT_PORT,
        help = "The port of the monitor"
    )]
    pub port: u16,

    /// Whether to enable OpenTelemetry.
    #[arg(
        long = "enable-otel",
        env = "MIDEN_MONITOR_ENABLE_OTEL",
        action = clap::ArgAction::SetTrue,
        default_value_t = true,
        help = "Whether to enable OpenTelemetry"
    )]
    pub enable_otel: bool,

    /// Whether to disable the network transaction service checks (enabled by default). The network
    /// transaction service is a network account with a counter deployed at startup and incremented
    /// by sending a transaction to it.
    #[arg(
        long = "disable-ntx-service",
        env = "MIDEN_MONITOR_DISABLE_NTX_SERVICE",
        action = clap::ArgAction::SetTrue,
        default_value_t = false,
        help = "Whether to disable the network transaction service checks (enabled by default). The
        network transaction service is a network account with a counter deployed at startup and
        incremented by sending a transaction to it."
    )]
    pub disable_ntx_service: bool,

    /// Path for the counter program network account file.
    #[arg(
        long = "counter-filepath",
        env = "MIDEN_MONITOR_COUNTER_FILEPATH",
        default_value = "counter_program.mac",
        help = "Path where the counter account is located"
    )]
    pub counter_filepath: PathBuf,

    /// Path for the wallet account file.
    #[arg(
        long = "wallet-filepath",
        env = "MIDEN_MONITOR_WALLET_FILEPATH",
        default_value = "wallet_account.mac",
        help = "Path where the wallet account is located"
    )]
    pub wallet_filepath: PathBuf,

    /// The interval at which to send the increment counter transaction.
    #[arg(
        long = "counter-increment-interval",
        env = "MIDEN_MONITOR_COUNTER_INCREMENT_INTERVAL",
        default_value = "30s",
        value_parser = humantime::parse_duration,
        help = "The interval at which to send the increment counter transaction"
    )]
    pub counter_increment_interval: Duration,

    /// Maximum time to wait for the counter update after submitting a transaction.
    #[arg(
        long = "counter-latency-timeout",
        env = "MIDEN_MONITOR_COUNTER_LATENCY_TIMEOUT",
        default_value = "2m",
        value_parser = humantime::parse_duration,
        help = "Maximum time to wait for a counter update after submitting a transaction"
    )]
    pub counter_latency_timeout: Duration,

    /// The timeout for the outgoing requests.
    #[arg(
        long = "request-timeout",
        env = "MIDEN_MONITOR_REQUEST_TIMEOUT",
        default_value = "10s",
        value_parser = humantime::parse_duration,
        help = "The timeout for the outgoing requests"
    )]
    pub request_timeout: Duration,

    /// The URL of the explorer service.
    #[arg(
        long = "explorer-url",
        env = "MIDEN_MONITOR_EXPLORER_URL",
        help = "The URL of the explorer service"
    )]
    pub explorer_url: Option<Url>,

    /// The URL of the note transport service.
    #[arg(
        long = "note-transport-url",
        env = "MIDEN_MONITOR_NOTE_TRANSPORT_URL",
        help = "The URL of the note transport service"
    )]
    pub note_transport_url: Option<Url>,

    /// Maximum time without a chain tip update before marking RPC as unhealthy.
    ///
    /// If the chain tip does not increment within this duration, the RPC service will be
    /// marked as unhealthy with a stale chain tip error.
    #[arg(
        long = "stale-chain-tip-threshold",
        env = "MIDEN_MONITOR_STALE_CHAIN_TIP_THRESHOLD",
        default_value = "1m",
        value_parser = humantime::parse_duration,
        help = "Maximum time without a chain tip update before marking RPC as unhealthy"
    )]
    pub stale_chain_tip_threshold: Duration,
}
