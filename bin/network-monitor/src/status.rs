//! Network monitor status checker.
//!
//! This module contains the logic for checking the status of network services.
//! Individual status checker tasks send updates via watch channels to the web server.

use std::time::Duration;

use miden_node_proto::clients::{
    Builder as ClientBuilder,
    RemoteProverProxyStatusClient,
    RpcClient,
};
use miden_node_proto::generated as proto;
use miden_node_proto::generated::rpc::{BlockProducerStatus, RpcStatus, StoreStatus};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tokio::time::MissedTickBehavior;
use tracing::{debug, info, instrument};
use url::Url;

use crate::faucet::FaucetTestDetails;
use crate::remote_prover::{ProofType, ProverTestDetails};
use crate::{COMPONENT, current_unix_timestamp_secs};

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

// STATUS
// ================================================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Status {
    Healthy,
    Unhealthy,
    Unknown,
}

impl From<String> for Status {
    fn from(value: String) -> Self {
        match value.as_str() {
            "HEALTHY" | "connected" => Status::Healthy,
            "UNHEALTHY" | "disconnected" => Status::Unhealthy,
            _ => Status::Unknown,
        }
    }
}

impl From<proto::remote_prover::WorkerHealthStatus> for Status {
    fn from(value: proto::remote_prover::WorkerHealthStatus) -> Self {
        match value {
            proto::remote_prover::WorkerHealthStatus::Unknown => Status::Unknown,
            proto::remote_prover::WorkerHealthStatus::Healthy => Status::Healthy,
            proto::remote_prover::WorkerHealthStatus::Unhealthy => Status::Unhealthy,
        }
    }
}

// SERVICE STATUS
// ================================================================================================

/// Status of a service.
///
/// This struct contains the status of a service, the last time it was checked, and any errors that
/// occurred. It also contains the details of the service, which is a union of the details of the
/// service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceStatus {
    pub name: String,
    pub status: Status,
    pub last_checked: u64,
    pub error: Option<String>,
    pub details: ServiceDetails,
}

/// Details of the increment service.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IncrementDetails {
    /// Number of successful counter increments.
    pub success_count: u64,
    /// Number of failed counter increments.
    pub failure_count: u64,
    /// Last transaction ID (if available).
    pub last_tx_id: Option<String>,
    /// Last measured latency in blocks from submission to state update.
    pub last_latency_blocks: Option<u32>,
}

/// Details about an in-flight latency measurement.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PendingLatencyDetails {
    /// Block height returned when the transaction was submitted.
    pub submit_height: u32,
    /// Counter value we expect to see once the transaction is applied.
    pub target_value: u64,
}

/// Details of the counter tracking service.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CounterTrackingDetails {
    /// Current counter value observed on-chain (if available).
    pub current_value: Option<u64>,
    /// Expected counter value based on successful increments sent.
    pub expected_value: Option<u64>,
    /// Last time the counter value was successfully updated.
    pub last_updated: Option<u64>,
    /// Number of pending increments (expected - current).
    pub pending_increments: Option<u64>,
}

/// Details of the explorer service.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExplorerStatusDetails {
    pub block_number: u64,
    pub timestamp: u64,
    pub number_of_transactions: u64,
    pub number_of_nullifiers: u64,
    pub number_of_notes: u64,
    pub number_of_account_updates: u64,
    pub block_commitment: String,
    pub chain_commitment: String,
    pub proof_commitment: String,
}

/// Details of the note transport service.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NoteTransportStatusDetails {
    pub url: String,
    pub serving_status: String,
}

/// Details of a service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServiceDetails {
    RpcStatus(RpcStatusDetails),
    RemoteProverStatus(RemoteProverStatusDetails),
    RemoteProverTest(ProverTestDetails),
    FaucetTest(FaucetTestDetails),
    NtxIncrement(IncrementDetails),
    NtxTracking(CounterTrackingDetails),
    ExplorerStatus(ExplorerStatusDetails),
    NoteTransportStatus(NoteTransportStatusDetails),
    Error,
}

/// Details of an RPC service.
///
/// This struct contains the details of an RPC service, which is a union of the details of the RPC
/// service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcStatusDetails {
    /// The URL of the RPC service (used by the frontend for gRPC-Web probing).
    pub url: String,
    pub version: String,
    pub genesis_commitment: Option<String>,
    pub store_status: Option<StoreStatusDetails>,
    pub block_producer_status: Option<BlockProducerStatusDetails>,
}

/// Details of a store service.
///
/// This struct contains the details of a store service, which is a union of the details of the
/// store service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreStatusDetails {
    pub version: String,
    pub status: Status,
    pub chain_tip: u32,
}

/// Details of a block producer service.
///
/// This struct contains the details of a block producer service, which is a union of the details
/// of the block producer service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockProducerStatusDetails {
    pub version: String,
    pub status: Status,
    /// The block producer's current view of the chain tip height.
    pub chain_tip: u32,
    /// Mempool statistics for this block producer.
    pub mempool: MempoolStatusDetails,
}

/// Details about the block producer's mempool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolStatusDetails {
    /// Number of transactions currently in the mempool waiting to be batched.
    pub unbatched_transactions: u64,
    /// Number of batches currently being proven.
    pub proposed_batches: u64,
    /// Number of proven batches waiting for block inclusion.
    pub proven_batches: u64,
}

/// Details of a remote prover service.
///
/// This struct contains the details of a remote prover service, which is a union of the details
/// of the remote prover service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteProverStatusDetails {
    pub url: String,
    pub version: String,
    pub supported_proof_type: ProofType,
    pub workers: Vec<WorkerStatusDetails>,
}

/// Details of a worker service.
///
/// This struct contains the details of a worker service, which is a union of the details of the
/// worker service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerStatusDetails {
    pub name: String,
    pub version: String,
    pub status: Status,
}

/// Status of a network.
///
/// This struct contains the status of a network, which is a union of the status of the network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStatus {
    pub services: Vec<ServiceStatus>,
    pub last_updated: u64,
}

// FROM IMPLEMENTATIONS
// ================================================================================================

/// From implementations for converting gRPC types to domain types
///
/// This implementation converts a `StoreStatus` to a `StoreStatusDetails`.
impl From<StoreStatus> for StoreStatusDetails {
    fn from(value: StoreStatus) -> Self {
        Self {
            version: value.version,
            status: value.status.into(),
            chain_tip: value.chain_tip,
        }
    }
}

impl From<BlockProducerStatus> for BlockProducerStatusDetails {
    fn from(value: BlockProducerStatus) -> Self {
        // We assume all supported nodes expose mempool statistics.
        let mempool_stats = value
            .mempool_stats
            .expect("block producer status must include mempool statistics");

        Self {
            version: value.version,
            status: value.status.into(),
            chain_tip: value.chain_tip,
            mempool: MempoolStatusDetails {
                unbatched_transactions: mempool_stats.unbatched_transactions,
                proposed_batches: mempool_stats.proposed_batches,
                proven_batches: mempool_stats.proven_batches,
            },
        }
    }
}

impl From<proto::remote_prover::ProxyWorkerStatus> for WorkerStatusDetails {
    fn from(value: proto::remote_prover::ProxyWorkerStatus) -> Self {
        let status =
            proto::remote_prover::WorkerHealthStatus::try_from(value.status).unwrap().into();

        Self {
            name: value.name,
            version: value.version,
            status,
        }
    }
}

impl RemoteProverStatusDetails {
    pub fn from_proxy_status(status: proto::remote_prover::ProxyStatus, url: String) -> Self {
        let proof_type = proto::remote_prover::ProofType::try_from(status.supported_proof_type)
            .unwrap()
            .into();

        let workers: Vec<WorkerStatusDetails> =
            status.workers.into_iter().map(WorkerStatusDetails::from).collect();

        Self {
            url,
            version: status.version,
            supported_proof_type: proof_type,
            workers,
        }
    }
}

impl RpcStatusDetails {
    /// Creates `RpcStatusDetails` from a gRPC `RpcStatus` response and the configured URL.
    pub fn from_rpc_status(status: RpcStatus, url: String) -> Self {
        Self {
            url,
            version: status.version,
            genesis_commitment: status.genesis_commitment.as_ref().map(|gc| format!("{gc:?}")),
            store_status: status.store.map(StoreStatusDetails::from),
            block_producer_status: status.block_producer.map(BlockProducerStatusDetails::from),
        }
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
                    return ServiceStatus {
                        name: "RPC".to_string(),
                        status: Status::Unhealthy,
                        last_checked: current_time,
                        error: Some(format!(
                            "Chain tip {} has not changed for {} seconds",
                            store_status.chain_tip, stale_duration
                        )),
                        details: ServiceDetails::RpcStatus(rpc_details),
                    };
                }
            }

            ServiceStatus {
                name: "RPC".to_string(),
                status: Status::Healthy,
                last_checked: current_time,
                error: None,
                details: ServiceDetails::RpcStatus(rpc_details),
            }
        },
        Err(e) => {
            debug!(target: COMPONENT, error = %e, "RPC status check failed");
            ServiceStatus {
                name: "RPC".to_string(),
                status: Status::Unhealthy,
                last_checked: current_time,
                error: Some(e.to_string()),
                details: ServiceDetails::Error,
            }
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

        let current_time = current_unix_timestamp_secs();

        let status = check_remote_prover_status(
            &mut remote_prover,
            name.clone(),
            url_str.clone(),
            current_time,
        )
        .await;

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
/// * `current_time` - The current time.
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
    current_time: u64,
) -> ServiceStatus {
    match remote_prover.status(()).await {
        Ok(response) => {
            let status = response.into_inner();

            // Use the new method to convert gRPC status to domain type
            let remote_prover_details = RemoteProverStatusDetails::from_proxy_status(status, url);

            // Determine overall health based on worker statuses
            let overall_health = if remote_prover_details.workers.is_empty() {
                Status::Unknown
            } else if remote_prover_details.workers.iter().any(|w| w.status == Status::Healthy) {
                Status::Healthy
            } else {
                Status::Unhealthy
            };

            ServiceStatus {
                name: display_name.clone(),
                status: overall_health,
                last_checked: current_time,
                error: None,
                details: ServiceDetails::RemoteProverStatus(remote_prover_details),
            }
        },
        Err(e) => {
            debug!(target: COMPONENT, prover_name = %display_name, error = %e, "Remote prover status check failed");
            ServiceStatus {
                name: display_name,
                status: Status::Unhealthy,
                last_checked: current_time,
                error: Some(e.to_string()),
                details: ServiceDetails::Error,
            }
        },
    }
}
