//! Start command implementation.
//!
//! This module contains the implementation for starting the network monitoring service.

use anyhow::Result;
use miden_node_tracing::{OpenTelemetry, info, miden_instrument};

use crate::config::MonitorConfig;
use crate::frontend::ServerState;
use crate::monitor::tasks::Tasks;
use crate::{COMPONENT, LOG_TARGET};

/// Start the network monitoring service.
///
/// This function initializes all monitoring tasks including RPC status checking,
/// remote prover testing, faucet testing, and the web frontend.
#[miden_instrument(
    parent = None,
    target = COMPONENT,
    name = "network_monitor.start_monitor",
    level = "info",
    fields(
        port = config.port,
    ),
    ret(level = "debug"),
    err,
)]
pub async fn start_monitor(config: MonitorConfig) -> Result<()> {
    validate_startup_config(&config)?;

    info!(target: LOG_TARGET, "Loaded configuration", port = config.port);

    let _otel_guard =
        miden_node_tracing::setup_tracing(OpenTelemetry::from_env().with_name("monitor"))?;

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

/// Validates configuration which is required before background monitoring tasks are started.
fn validate_startup_config(config: &MonitorConfig) -> Result<()> {
    if !config.disable_ntx_service {
        config.fee_faucet_id()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[test]
    fn status_only_prover_monitoring_does_not_require_a_fee_faucet_at_startup() {
        let mut config = MonitorConfig::parse_from([
            "network-monitor",
            "--disable-ntx-service",
            "--remote-prover-urls",
            "http://127.0.0.1:50051",
        ]);
        config.fee_faucet_id = None;

        validate_startup_config(&config)
            .expect("prover status discovery must start without transaction-probe configuration");
    }

    #[test]
    fn ntx_monitoring_still_requires_a_fee_faucet_at_startup() {
        let mut config = MonitorConfig::parse_from(["network-monitor"]);
        config.fee_faucet_id = None;

        let error = validate_startup_config(&config)
            .expect_err("NTX monitoring always executes transactions and needs a fee faucet");
        assert!(error.to_string().contains("--fee-faucet-id"));
    }
}
