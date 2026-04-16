//! Network monitor status checker tasks.
//!
//! This module contains the logic for checking the status of network services.
//! Individual status checker tasks send updates via watch channels to the web server.
//!
//! Type definitions live in [`crate::service_status`] and are re-exported here for convenience.

use std::time::Duration;

use miden_node_proto::clients::{
    Builder as ClientBuilder,
    RemoteProverProxyStatusClient,
    RpcClient,
};
use tokio::sync::watch;
use tokio::time::MissedTickBehavior;
use tracing::{debug, info, instrument};
use url::Url;

use crate::COMPONENT;
pub use crate::service_status::*;

// STALE CHAIN TIP TRACKER
// ================================================================================================

/// Tracks the chain tip and detects when it becomes stale.
///
/// This struct monitors the chain tip from RPC status responses and determines if the chain
/// has stopped making progress by comparing the time since the last chain tip change against
/// a configurable threshold.
#[derive(Debug)]
pub struct StaleChainTracker {
    /// The last observed chain tip from the store.
    last_chain_tip: Option<u32>,
    /// Unix timestamp when the chain tip was last observed to change.
    last_chain_tip_update: Option<u64>,
    /// Maximum time without a chain tip update before marking as stale.
    stale_threshold_secs: u64,
}

impl StaleChainTracker {
    /// Creates a new stale chain tracker with the given threshold.
    pub fn new(stale_threshold: Duration) -> Self {
        Self {
            last_chain_tip: None,
            last_chain_tip_update: None,
            stale_threshold_secs: stale_threshold.as_secs(),
        }
    }

    /// Updates the tracker with a new chain tip observation and returns whether the chain is
    /// stale.
    ///
    /// The chain is considered stale if the tip hasn't changed for longer than the configured
    /// threshold
    pub fn update(&mut self, chain_tip: u32, current_time: u64) -> Option<u64> {
        match self.last_chain_tip {
            Some(last_tip) if last_tip == chain_tip => {
                if let Some(last_update) = self.last_chain_tip_update {
                    let elapsed = current_time.saturating_sub(last_update);
                    if elapsed > self.stale_threshold_secs {
                        return Some(elapsed);
                    }
                }
            },
            _ => {
                self.last_chain_tip = Some(chain_tip);
                self.last_chain_tip_update = Some(current_time);
            },
        }
        None
    }
}

// RPC STATUS CHECKER
// ================================================================================================

/// Runs a task that continuously checks RPC status and updates a watch channel.
///
/// This function spawns a task that periodically checks the RPC service status
/// and sends updates through a watch channel. It also detects stale chain tips
/// and marks the RPC as unhealthy if the chain tip hasn't changed for longer
/// than the configured threshold.
///
/// # Arguments
///
/// * `rpc_url` - The URL of the RPC service.
/// * `status_sender` - The sender for the watch channel.
/// * `status_check_interval` - The interval at which to check the status of the services.
/// * `request_timeout` - The timeout for outgoing requests.
/// * `stale_chain_tip_threshold` - Maximum time without a chain tip update before marking as
///   unhealthy.
///
/// # Returns
///
/// `Ok(())` if the task completes successfully, or an error if the task fails.
pub async fn run_rpc_status_task(
    rpc_url: Url,
    status_sender: watch::Sender<ServiceStatus>,
    status_check_interval: Duration,
    request_timeout: Duration,
    stale_chain_tip_threshold: Duration,
) {
    let url_str = rpc_url.to_string();
    let mut rpc = ClientBuilder::new(rpc_url)
        .with_tls()
        .expect("TLS is enabled")
        .with_timeout(request_timeout)
        .without_metadata_version()
        .without_metadata_genesis()
        .without_otel_context_injection()
        .connect_lazy::<RpcClient>();

    let mut interval = tokio::time::interval(status_check_interval);
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let mut stale_tracker = StaleChainTracker::new(stale_chain_tip_threshold);

    loop {
        interval.tick().await;

        let current_time = current_unix_timestamp_secs();

        let status =
            check_rpc_status(&mut rpc, url_str.clone(), current_time, &mut stale_tracker).await;

        // Send the status update; exit if no receivers (shutdown signal)
        if status_sender.send(status).is_err() {
            info!("No receivers for RPC status updates, shutting down");
            return;
        }
    }
}

/// Checks the status of the RPC service.
///
/// This function checks the status of the RPC service and detects stale chain tips.
/// If the chain tip hasn't changed for longer than the configured threshold, the RPC
/// is marked as unhealthy.
///
/// # Arguments
///
/// * `rpc` - The RPC client.
/// * `url` - The URL of the RPC service.
/// * `current_time` - The current time.
/// * `stale_tracker` - Tracker for detecting stale chain tips.
///
/// # Returns
///
/// A `ServiceStatus` containing the status of the RPC service.
#[instrument(
    parent = None,
    target = COMPONENT,
    name = "network_monitor.status.check_rpc_status",
    skip_all,
    level = "info",
    ret(level = "debug")
)]
pub(crate) async fn check_rpc_status(
    rpc: &mut miden_node_proto::clients::RpcClient,
    url: String,
    current_time: u64,
    stale_tracker: &mut StaleChainTracker,
) -> ServiceStatus {
    match rpc.status(()).await {
        Ok(response) => {
            let status = response.into_inner();
            let rpc_details = RpcStatusDetails::from_rpc_status(status, url);

            // Check for stale chain tip using the store's chain tip
            if let Some(store_status) = &rpc_details.store_status {
                if let Some(stale_duration) =
                    stale_tracker.update(store_status.chain_tip, current_time)
                {
                    debug!(
                        target: COMPONENT,
                        chain_tip = store_status.chain_tip,
                        stale_duration_secs = stale_duration,
                        "Chain tip is stale"
                    );
                    return ServiceStatus::unhealthy(
                        "RPC",
                        format!(
                            "Chain tip {} has not changed for {} seconds",
                            store_status.chain_tip, stale_duration
                        ),
                        ServiceDetails::RpcStatus(rpc_details),
                    );
                }
            }

            ServiceStatus::healthy("RPC", ServiceDetails::RpcStatus(rpc_details))
        },
        Err(e) => {
            debug!(target: COMPONENT, error = %e, "RPC status check failed");
            ServiceStatus::error("RPC", e)
        },
    }
}

// REMOTE PROVER STATUS CHECKER
// ================================================================================================

/// Runs a task that continuously checks remote prover status and updates a watch channel.
///
/// This function spawns a task that periodically checks a remote prover service status
/// and sends updates through a watch channel.
///
/// # Arguments
///
/// * `prover_url` - The URL of the remote prover service.
/// * `name` - The name of the remote prover.
/// * `status_sender` - The sender for the watch channel.
/// * `status_check_interval` - The interval at which to check the status of the services.
///
/// # Returns
///
/// `Ok(())` if the monitoring task runs and completes successfully, or an error if there are
/// connection issues or failures while checking the remote prover status.
pub async fn run_remote_prover_status_task(
    prover_url: Url,
    name: String,
    status_sender: watch::Sender<ServiceStatus>,
    status_check_interval: Duration,
    request_timeout: Duration,
) {
    let url_str = prover_url.to_string();
    let mut remote_prover = ClientBuilder::new(prover_url)
        .with_tls()
        .expect("TLS is enabled")
        .with_timeout(request_timeout)
        .without_metadata_version()
        .without_metadata_genesis()
        .without_otel_context_injection()
        .connect_lazy::<RemoteProverProxyStatusClient>();

    let mut interval = tokio::time::interval(status_check_interval);
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        interval.tick().await;

        let status =
            check_remote_prover_status(&mut remote_prover, name.clone(), url_str.clone()).await;

        // Send the status update; exit if no receivers (shutdown signal)
        if status_sender.send(status).is_err() {
            info!("No receivers for remote prover status updates, shutting down");
            return;
        }
    }
}

/// Checks the status of the remote prover service.
///
/// This function checks the status of the remote prover service.
///
/// # Arguments
///
/// * `remote_prover` - The remote prover client.
/// * `name` - The name of the remote prover.
/// * `url` - The URL of the remote prover.
///
/// # Returns
///
/// A `ServiceStatus` containing the status of the remote prover service.
#[instrument(
    parent = None,
    target = COMPONENT,
    name = "network_monitor.status.check_remote_prover_status",
    skip_all,
    level = "info",
    ret(level = "debug")
)]
pub(crate) async fn check_remote_prover_status(
    remote_prover: &mut miden_node_proto::clients::RemoteProverProxyStatusClient,
    display_name: String,
    url: String,
) -> ServiceStatus {
    match remote_prover.status(()).await {
        Ok(response) => {
            let status = response.into_inner();

            // Use the new method to convert gRPC status to domain type
            let remote_prover_details = RemoteProverStatusDetails::from_proxy_status(status, url);

            // Determine overall health based on worker statuses.
            // All workers must be healthy for the prover to be considered healthy.
            let no_workers = remote_prover_details.workers.is_empty();
            let all_healthy =
                remote_prover_details.workers.iter().all(|w| w.status == Status::Healthy);
            let unhealthy_worker_names: Vec<_> = remote_prover_details
                .workers
                .iter()
                .filter(|w| w.status != Status::Healthy)
                .map(|w| w.name.clone())
                .collect();
            let details = ServiceDetails::RemoteProverStatus(remote_prover_details);

            if no_workers {
                ServiceStatus::unknown(display_name, details)
            } else if all_healthy {
                ServiceStatus::healthy(display_name, details)
            } else {
                ServiceStatus::unhealthy(
                    display_name,
                    format!("unhealthy workers: {}", unhealthy_worker_names.join(", ")),
                    details,
                )
            }
        },
        Err(e) => {
            debug!(target: COMPONENT, prover_name = %display_name, error = %e, "Remote prover status check failed");
            ServiceStatus::error(display_name, e)
        },
    }
}
