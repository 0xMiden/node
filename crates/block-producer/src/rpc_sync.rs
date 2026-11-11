use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use miden_node_proto::clients::RpcClient;
use miden_node_store::state::{BlockWriter, ProofWriter, State};
use miden_node_tracing::{debug, info, warn};
use miden_node_utils::shutdown::CancellationToken;
use miden_node_utils::tasks::Tasks;
use miden_protocol::block::BlockNumber;
use tonic_health::ServingStatus;
use tonic_health::server::HealthReporter;

mod blocks;
mod proofs;

use blocks::BlockSync;
use proofs::ProofSync;

pub(crate) const RECONNECT_DELAY: Duration = Duration::from_secs(5);

// RPC READINESS
// ================================================================================================

/// Tracks readiness of the RPC API service for a full-node.
///
/// Holds the gRPC [`HealthReporter`] and the readiness threshold. Created by [`Rpc::serve`]
/// once the health pair is available and passed directly into [`BlockSync`].
#[derive(Clone)]
pub struct RpcReadiness {
    reporter: HealthReporter,
    threshold: u32,
    state: Arc<AtomicU8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReadinessTransition {
    InitialNotReady,
    BecameReady,
    BecameNotReady,
    Unchanged,
}

impl RpcReadiness {
    const SERVICE_NAME: &'static str = "miden.node.v1.NodeService";
    const UNKNOWN: u8 = 0;
    const NOT_READY: u8 = 1;
    const READY: u8 = 2;

    pub fn new(reporter: HealthReporter, threshold: u32) -> Self {
        Self {
            reporter,
            threshold,
            state: Arc::new(AtomicU8::new(Self::UNKNOWN)),
        }
    }

    /// Updates the RPC service health status based on the upstream/local tip gap.
    pub async fn update(&self, upstream_tip: BlockNumber, local_tip: BlockNumber) {
        let gap = upstream_tip.as_u32().saturating_sub(local_tip.as_u32());
        let ready = gap <= self.threshold;
        let status = if ready {
            ServingStatus::Serving
        } else {
            ServingStatus::NotServing
        };
        self.reporter.set_service_status(Self::SERVICE_NAME, status).await;

        match self.record_transition(ready) {
            ReadinessTransition::BecameReady => {
                info!(
                    "Node ready",
                    service.name = "miden-node",
                    service.version = env!("CARGO_PKG_VERSION"),
                    node.role = "full",
                    block.number = local_tip,
                    sync.upstream_block = upstream_tip,
                    sync.block_gap = gap,
                    sync.ready_threshold = self.threshold
                );
            },
            ReadinessTransition::BecameNotReady => {
                warn!(
                    "Node no longer ready",
                    block.number = local_tip,
                    sync.upstream_block = upstream_tip,
                    sync.block_gap = gap,
                    sync.ready_threshold = self.threshold
                );
            },
            ReadinessTransition::InitialNotReady => {
                debug!(
                    "Node synchronizing",
                    block.number = local_tip,
                    sync.upstream_block = upstream_tip,
                    sync.block_gap = gap,
                    sync.ready_threshold = self.threshold
                );
            },
            ReadinessTransition::Unchanged => {},
        }
    }

    fn record_transition(&self, ready: bool) -> ReadinessTransition {
        let next = if ready { Self::READY } else { Self::NOT_READY };
        match self.state.swap(next, Ordering::Relaxed) {
            previous if previous == next => ReadinessTransition::Unchanged,
            Self::UNKNOWN if ready => ReadinessTransition::BecameReady,
            Self::UNKNOWN => ReadinessTransition::InitialNotReady,
            Self::READY => ReadinessTransition::BecameNotReady,
            Self::NOT_READY => ReadinessTransition::BecameReady,
            _ => unreachable!("readiness state is one of the declared constants"),
        }
    }
}

// RPC SYNC
// ================================================================================================

/// Synchronizes local state from an upstream RPC service.
pub struct RpcSync {
    /// Read-only store state, used by both loops to read tips and subscribe to commits.
    pub state: Arc<State>,
    /// The store's block-write capability, consumed by the block sync loop.
    pub block_writer: BlockWriter,
    /// The store's proof-write capability, consumed by the proof sync loop.
    pub proof_writer: ProofWriter,
    pub source_rpc: RpcClient,
    pub readiness: RpcReadiness,
}

impl RpcSync {
    /// Runs the block and proof synchronization loops until one exits unexpectedly.
    pub async fn run(self, shutdown: CancellationToken) -> anyhow::Result<()> {
        let mut tasks = Tasks::new();
        let block_sync = BlockSync {
            state: Arc::clone(&self.state),
            writer: self.block_writer,
            source_rpc: self.source_rpc.clone(),
            readiness: self.readiness,
        };
        let proof_sync = ProofSync {
            state: self.state,
            writer: self.proof_writer,
            source_rpc: self.source_rpc,
        };

        tasks.spawn("block-sync", block_sync.run(shutdown.clone()));
        tasks.spawn("proof-sync", proof_sync.run(shutdown.clone()));

        tasks.join_next_or_cancelled(shutdown).await
    }
}

#[cfg(test)]
mod block_tests;

#[cfg(test)]
mod readiness_tests {
    use super::*;

    #[test]
    fn readiness_transitions_are_emitted_once_per_state_change() {
        let (reporter, _service) = tonic_health::server::health_reporter();
        let readiness = RpcReadiness::new(reporter, 10);

        assert_eq!(readiness.record_transition(false), ReadinessTransition::InitialNotReady,);
        assert_eq!(readiness.record_transition(false), ReadinessTransition::Unchanged,);
        assert_eq!(readiness.record_transition(true), ReadinessTransition::BecameReady,);
        assert_eq!(readiness.record_transition(true), ReadinessTransition::Unchanged,);
        assert_eq!(readiness.record_transition(false), ReadinessTransition::BecameNotReady,);
    }
}
