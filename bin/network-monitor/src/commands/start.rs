//! Start command implementation.
//!
//! This module contains the implementation for starting the network monitoring service.

use anyhow::Result;
use miden_node_utils::logging::OpenTelemetry;
use miden_node_utils::tracing::miden_instrument;
use tracing::info;

use crate::COMPONENT;
use crate::config::MonitorConfig;
use crate::frontend::ServerState;
use crate::monitor::tasks::Tasks;

/// Start the network monitoring service.
///
/// This function initializes all monitoring tasks including RPC status checking,
/// remote prover testing, faucet testing, and the web frontend.
#[miden_instrument(
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
    info!("Loaded configuration: {:?}", config);

    let _otel_guard =
        miden_node_utils::logging::setup_tracing(OpenTelemetry::from_env().with_name("monitor"))?;

    let mut tasks = Tasks::new();

    let rpc_rx = tasks.spawn_rpc_checker(&config);

    let prover_rxs = tasks.spawn_prover_tasks(&config);

    let faucet_rx = config.faucet_url.is_some().then(|| tasks.spawn_faucet(&config));

    let explorer_rx = config.explorer_url.is_some().then(|| tasks.spawn_explorer_checker(&config));

    let (ntx_increment_rx, ntx_tracking_rx) = if config.disable_ntx_service {
        (None, None)
    } else {
        let (increment_rx, tracking_rx) = tasks.spawn_ntx_service(&config);
        (Some(increment_rx), Some(tracking_rx))
    };

    let note_transport_rx = config
        .note_transport_url
        .is_some()
        .then(|| tasks.spawn_note_transport_checker(&config));

    let validator_rx =
        config.validator_url.is_some().then(|| tasks.spawn_validator_checker(&config));

    // Build the flat services Vec in the order the dashboard expects to render cards.
    let services = std::iter::once(rpc_rx)
        .chain(prover_rxs)
        .chain(faucet_rx)
        .chain(explorer_rx)
        .chain(ntx_increment_rx)
        .chain(ntx_tracking_rx)
        .chain(note_transport_rx)
        .chain(validator_rx)
        .collect();

    let server_state = ServerState {
        services,
        monitor_version: env!("CARGO_PKG_VERSION").to_string(),
        network_name: config.network_name.clone(),
    };
    tasks.spawn_http_server(server_state, &config);

    tasks.handle_failure().await
}
