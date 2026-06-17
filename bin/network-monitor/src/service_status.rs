//! Service status types and constructors for the network monitor.
//!
//! This module defines the data model for service health reporting: the [`ServiceStatus`] struct
//! with its builder methods, the [`ServiceDetails`] enum covering all monitored service types,
//! and the corresponding detail structs.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use miden_node_proto::generated as proto;
use miden_node_proto::generated::rpc::{BlockProducerStatus, RpcStatus};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::COMPONENT;
use crate::faucet::FaucetTestDetails;
use crate::remote_prover::{ProofType, ProverTestDetails};

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

impl ServiceStatus {
    /// Creates a healthy service status with the current timestamp.
    pub fn healthy(name: impl Into<String>, details: ServiceDetails) -> Self {
        Self {
            name: name.into(),
            status: Status::Healthy,
            last_checked: current_unix_timestamp_secs(),
            error: None,
            details,
        }
    }

    /// Creates an unhealthy service status with the current timestamp and an error message.
    #[expect(clippy::needless_pass_by_value)]
    pub fn unhealthy(
        name: impl Into<String>,
        error: impl ToString,
        details: ServiceDetails,
    ) -> Self {
        Self {
            name: name.into(),
            status: Status::Unhealthy,
            last_checked: current_unix_timestamp_secs(),
            error: Some(error.to_string()),
            details,
        }
    }

    /// Creates an unknown service status with the current timestamp.
    pub fn unknown(name: impl Into<String>, details: ServiceDetails) -> Self {
        Self {
            name: name.into(),
            status: Status::Unknown,
            last_checked: current_unix_timestamp_secs(),
            error: None,
            details,
        }
    }

    /// Creates an unhealthy service status with [`ServiceDetails::Error`] details.
    #[expect(clippy::needless_pass_by_value)]
    pub fn error(name: impl Into<String>, error: impl ToString) -> Self {
        Self {
            name: name.into(),
            status: Status::Unhealthy,
            last_checked: current_unix_timestamp_secs(),
            error: Some(error.to_string()),
            details: ServiceDetails::Error,
        }
    }

    /// Overrides the `last_checked` timestamp on an existing status.
    ///
    /// Useful when composing a new status from pre-existing data where we want to preserve the
    /// original check timestamp instead of using the moment of construction.
    #[must_use]
    pub fn with_last_checked(mut self, ts: u64) -> Self {
        self.last_checked = ts;
        self
    }
}

// SERVICE DETAILS
// ================================================================================================

/// Details of a service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServiceDetails {
    RpcStatus(RpcStatusDetails),
    RemoteProverStatus(RemoteProverDetails),
    FaucetTest(FaucetTestDetails),
    NtxIncrement(IncrementDetails),
    NtxTracking(CounterTrackingDetails),
    ExplorerStatus(ExplorerStatusDetails),
    NoteTransportStatus(NoteTransportStatusDetails),
    ValidatorStatus(ValidatorStatusDetails),
    Error,
}

/// Remote prover status combined with its most recent test result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteProverDetails {
    pub status: RemoteProverStatusDetails,
    pub test: Option<ProverTestOutcome>,
}

/// Most recent outcome of a remote prover test task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProverTestOutcome {
    pub details: ProverTestDetails,
    pub status: Status,
    /// Error message from the most recent test attempt; `None` when the last attempt succeeded.
    pub error: Option<String>,
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
///
/// The `total_*` counters are network-wide totals sourced from the explorer's `overviewStats`
/// query, not per-block counts. `block_number`, `timestamp` and the commitments are still
/// taken from the latest block so that tip-drift against the RPC can be detected.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExplorerStatusDetails {
    pub block_number: u64,
    pub timestamp: u64,
    pub total_transactions: u64,
    pub total_nullifiers: u64,
    pub total_notes: u64,
    pub total_account_updates: u64,
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

/// Details of the validator service.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ValidatorStatusDetails {
    pub url: String,
    pub version: String,
    pub chain_tip: u32,
    pub validated_transactions_count: u64,
    pub signed_blocks_count: u64,
}

// RPC STATUS DETAILS
// ================================================================================================

/// Details of an RPC service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcStatusDetails {
    /// The URL of the RPC service (used by the frontend for gRPC-Web probing).
    pub url: String,
    pub version: String,
    pub genesis_commitment: Option<String>,
    pub chain_tip: u32,
    pub block_producer_status: Option<BlockProducerStatusDetails>,
}

/// Details of a store service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreStatusDetails {
    pub version: String,
    pub status: Status,
    pub chain_tip: u32,
}

/// Details of a block producer service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockProducerStatusDetails {
    pub version: String,
    pub status: Status,
    /// The block producer's current view of the chain tip height.
    pub chain_tip: u32,
    /// Mempool statistics for this block producer; `None` when the node did not report them.
    pub mempool: Option<MempoolStatusDetails>,
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

// REMOTE PROVER STATUS DETAILS
// ================================================================================================

/// Details of a remote prover service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteProverStatusDetails {
    pub url: String,
    pub version: String,
    pub supported_proof_type: ProofType,
    pub workers: Vec<WorkerStatusDetails>,
}

/// Details of a worker service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerStatusDetails {
    pub name: String,
    pub version: String,
    pub status: Status,
}

// NETWORK STATUS
// ================================================================================================

/// Status of the entire network, aggregating all service statuses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStatus {
    pub services: Vec<ServiceStatus>,
    pub last_updated: u64,
    pub monitor_version: String,
    pub network_name: String,
}

// FROM IMPLEMENTATIONS
// ================================================================================================

impl From<BlockProducerStatus> for BlockProducerStatusDetails {
    fn from(value: BlockProducerStatus) -> Self {
        // Mempool statistics are a message field, hence optional on the wire; a node version that
        // omits them must not bring the checker down.
        let mempool = value.mempool_stats.map(|stats| MempoolStatusDetails {
            unbatched_transactions: stats.unbatched_transactions,
            proposed_batches: stats.proposed_batches,
            proven_batches: stats.proven_batches,
        });

        Self {
            version: value.version,
            status: value.status.into(),
            chain_tip: value.chain_tip,
            mempool,
        }
    }
}

impl From<proto::remote_prover::ProxyWorkerStatus> for WorkerStatusDetails {
    fn from(value: proto::remote_prover::ProxyWorkerStatus) -> Self {
        // An out-of-range discriminant (e.g. from a newer prover version) degrades to Unknown
        // instead of panicking the checker task.
        let status = proto::remote_prover::WorkerHealthStatus::try_from(value.status).map_or_else(
            |_| {
                warn!(
                    target: COMPONENT,
                    raw = value.status,
                    worker = %value.name,
                    "unknown worker health status discriminant"
                );
                Status::Unknown
            },
            Status::from,
        );

        Self {
            name: value.name,
            version: value.version,
            status,
        }
    }
}

impl RemoteProverStatusDetails {
    pub fn from_proxy_status(status: proto::remote_prover::ProxyStatus, url: String) -> Self {
        // An out-of-range discriminant (e.g. from a newer prover version) degrades to Unknown
        // instead of panicking the checker task.
        let proof_type = proto::remote_prover::ProofType::try_from(status.supported_proof_type)
            .map_or_else(
                |_| {
                    warn!(
                        target: COMPONENT,
                        raw = status.supported_proof_type,
                        "unknown supported proof type discriminant"
                    );
                    ProofType::Unknown
                },
                ProofType::from,
            );

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
            chain_tip: status.chain_tip,
            block_producer_status: status.block_producer.map(BlockProducerStatusDetails::from),
        }
    }
}

// UTILITIES
// ================================================================================================

/// Gets the current Unix timestamp in seconds.
///
/// This function is infallible - if the system time is somehow before Unix epoch
/// (extremely unlikely), it returns 0.
pub fn current_unix_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_producer_status_without_mempool_stats_does_not_panic() {
        let proto_status = BlockProducerStatus {
            version: "1.0.0".to_string(),
            status: "HEALTHY".to_string(),
            chain_tip: 7,
            mempool_stats: None,
        };
        let details = BlockProducerStatusDetails::from(proto_status);
        assert!(details.mempool.is_none());
        assert_eq!(details.status, Status::Healthy);
        assert_eq!(details.chain_tip, 7);
    }

    #[test]
    fn worker_status_with_unknown_discriminant_degrades_to_unknown() {
        let proto_status = proto::remote_prover::ProxyWorkerStatus {
            name: "worker-1".to_string(),
            version: "1.0".to_string(),
            status: 99,
        };
        let details = WorkerStatusDetails::from(proto_status);
        assert_eq!(details.status, Status::Unknown);
        assert_eq!(details.name, "worker-1");
    }

    #[test]
    fn proxy_status_with_unknown_proof_type_degrades_to_unknown() {
        let proto_status = proto::remote_prover::ProxyStatus {
            version: "1.0".to_string(),
            supported_proof_type: 99,
            workers: vec![proto::remote_prover::ProxyWorkerStatus {
                name: "worker-1".to_string(),
                version: "1.0".to_string(),
                status: proto::remote_prover::WorkerHealthStatus::Healthy.into(),
            }],
        };
        let details = RemoteProverStatusDetails::from_proxy_status(proto_status, "url".to_string());
        assert!(matches!(details.supported_proof_type, ProofType::Unknown));
        assert_eq!(details.workers.len(), 1);
        assert_eq!(details.workers[0].status, Status::Healthy);
    }
}
