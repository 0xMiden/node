//! Start command implementation.
//!
//! This module contains the implementation for starting the network monitoring service.

use anyhow::Result;
use miden_node_utils::logging::OpenTelemetry;
use tracing::{debug, info, instrument, warn};

use crate::COMPONENT;
use crate::config::MonitorConfig;
use crate::frontend::ServerState;
use crate::monitor::tasks::Tasks;

/// Start the network monitoring service.
///
/// This function initializes all monitoring tasks including RPC status checking,
/// remote prover testing, faucet testing, and the web frontend.
#[instrument(
    parent = None,
    target = COMPONENT,
    name = "network_monitor.start_monitor",
    skip_all,
    level = "info",
    fields(port = %config.port),
    ret(level = "debug"),
    err
)]
pub async fn start_monitor(config: MonitorConfig) -> Result<()> {
    // Load configuration from command-line arguments and environment variables
    info!("Loaded configuration: {:?}", config);

    let _otel_guard = if config.enable_otel {
        miden_node_utils::logging::setup_tracing(OpenTelemetry::Enabled)?
    } else {
        miden_node_utils::logging::setup_tracing(OpenTelemetry::Disabled)?
    };

    let mut tasks = Tasks::new();

    // Initialize the RPC Status endpoint checker task.
    debug!(target: COMPONENT, "Initializing RPC status checker");
    let rpc_rx = tasks.spawn_rpc_checker(&config).await?;

    // Initialize the explorer status checker task.
    let explorer_rx = if config.explorer_url.is_some() {
        Some(tasks.spawn_explorer_checker(&config).await?)
    } else {
        None
    };

    // Initialize the note transport status checker task.
    let note_transport_rx = if config.note_transport_url.is_some() {
        Some(tasks.spawn_note_transport_checker(&config).await?)
    } else {
        None
    };

    // Initialize the prover checkers & tests tasks, only if URLs were provided.
    let prover_rxs = if config.remote_prover_urls.is_empty() {
        debug!(target: COMPONENT, "No remote prover URLs configured, skipping prover tasks");
        Vec::new()
    } else {
        debug!(target: COMPONENT, "Initializing prover checkers and tests");
        tasks.spawn_prover_tasks(&config).await?
    };

    // Initialize the faucet testing task.
    let faucet_rx = if config.faucet_url.is_some() {
        debug!(target: COMPONENT, "Initializing faucet testing task");
        Some(tasks.spawn_faucet(&config))
    } else {
        warn!("Faucet URL not configured, skipping faucet testing");
        None
    };

    // Initialize the counter increment and tracking tasks only if enabled.
    let (ntx_increment_rx, ntx_tracking_rx) = if config.disable_ntx_service {
        debug!(target: COMPONENT, "NTX service disabled, skipping counter increment task");
        (None, None)
    } else {
        debug!(target: COMPONENT, "Initializing counter increment task");
        let (increment_rx, tracking_rx) = tasks.spawn_ntx_service(&config).await?;
        (Some(increment_rx), Some(tracking_rx))
    };

    // Initialize HTTP server.
    debug!(target: COMPONENT, "Initializing HTTP server");
    let server_state = ServerState {
        rpc: rpc_rx,
        provers: prover_rxs,
        faucet: faucet_rx,
        ntx_increment: ntx_increment_rx,
        ntx_tracking: ntx_tracking_rx,
        explorer: explorer_rx,
        note_transport: note_transport_rx,
    };
    tasks.spawn_http_server(server_state, &config);

    tasks.handle_failure().await
}
