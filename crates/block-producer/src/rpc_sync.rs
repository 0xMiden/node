use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use anyhow::Context;
use miden_node_proto::clients::RpcClient;
use miden_node_proto::generated::rpc::{BlockSubscriptionRequest, ProofSubscriptionRequest};
use miden_node_store::state::{BlockWriter, ProofWriter, State};
use miden_node_tracing::{Instrument, debug, info, info_span, miden_instrument, warn};
use miden_node_utils::retry::{self, RetryableWithContext};
use miden_node_utils::shutdown::CancellationToken;
use miden_node_utils::tasks::Tasks;
use miden_protocol::block::{BlockNumber, SignedBlock};
use miden_protocol::vm::ExecutionProof;
use tokio_stream::StreamExt;
use tonic_health::ServingStatus;
use tonic_health::server::HealthReporter;

use crate::{COMPONENT, LOG_TARGET};

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
    const SERVICE_NAME: &'static str = "rpc.Api";
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
                    target: LOG_TARGET,
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
                    target: LOG_TARGET,
                    "Node no longer ready",
                    block.number = local_tip,
                    sync.upstream_block = upstream_tip,
                    sync.block_gap = gap,
                    sync.ready_threshold = self.threshold
                );
            },
            ReadinessTransition::InitialNotReady => {
                debug!(
                    target: LOG_TARGET,
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

// SYNC LOOP
// ================================================================================================

struct BlockSync {
    state: Arc<State>,
    writer: BlockWriter,
    source_rpc: RpcClient,
    readiness: RpcReadiness,
}

impl BlockSync {
    async fn run(self, shutdown: CancellationToken) -> anyhow::Result<()> {
        // `sync` needs `&mut self` (it applies blocks through the writer capability), so the retry
        // closure cannot lend out a borrow of a capture; thread `self` through as owned context
        // instead.
        let retry = (|mut sync: Self| {
            let shutdown = shutdown.clone();
            async move {
                let result = sync
                    .sync(shutdown)
                    .await
                    .and_then(|()| Err(anyhow::anyhow!("unexpected end of stream")));
                (sync, result)
            }
        })
        .retry(retry::constant(RECONNECT_DELAY, None))
        .context(self)
        .notify(|err, _| {
            warn!(
                err,
                target: LOG_TARGET,
                "Block sync failed, retrying",
                retry.delay_ms = RECONNECT_DELAY.as_millis() as u64
            );
        });

        tokio::select! {
            (_, result) = retry => result,
            () = shutdown.cancelled() => Ok(()),
        }
    }

    #[miden_instrument(
        target = COMPONENT,
        err,
    )]
    async fn sync(&mut self, shutdown: CancellationToken) -> anyhow::Result<()> {
        let local_tip = self.state.committed_tip();
        let mut client = self.source_rpc.clone();
        let upstream_tip =
            BlockNumber::from(client.status(tonic::Request::new(())).await?.into_inner().chain_tip);
        self.readiness.update(upstream_tip, local_tip).await;

        let block_from = local_tip.child().as_u32();
        info!(
            target: LOG_TARGET,
            "Connecting to upstream RPC for blocks",
            block.from = block_from
        );

        let mut stream = client
            .block_subscription(BlockSubscriptionRequest { block_from })
            .await?
            .into_inner();

        loop {
            let result = tokio::select! {
                () = shutdown.cancelled() => return Ok(()),
                result = stream.next() => result,
            };
            let Some(result) = result else {
                return Ok(());
            };
            let event = result?;
            let upstream_tip = BlockNumber::from(event.committed_chain_tip);
            let block: SignedBlock = event
                .block
                .ok_or_else(|| anyhow::anyhow!("upstream block event is missing its block"))?
                .try_into()
                .context("failed to decode block from upstream")?;
            // Each synced block gets its own root span: the surrounding `sync` span lives for the
            // whole subscription, so parenting under it would chain every block into one
            // never-exported trace.
            let block_span = info_span!(
                target: COMPONENT,
                parent: None,
                "sync_block",
                block.number = block.header().block_num().as_u32(),
            );
            self.writer.apply_block(block).instrument(block_span).await?;

            let local_tip = self.state.committed_tip();
            self.readiness.update(upstream_tip, local_tip).await;
        }
    }
}

struct ProofSync {
    state: Arc<State>,
    writer: ProofWriter,
    source_rpc: RpcClient,
}

impl ProofSync {
    /// Synchronizes block proofs from an upstream RPC service.
    ///
    /// Proof sync is intentionally coupled to block sync via the committed tip: a proof is only applied
    /// once its block has been committed locally. This means proof sync can stall if block sync falls
    /// behind, but that is acceptable — there is no value in streaming proofs for blocks that have not
    /// yet been applied.
    async fn run(self, shutdown: CancellationToken) -> anyhow::Result<()> {
        // `sync` needs `&mut self` (it commits proofs through the writer capability), so the retry
        // closure cannot lend out a borrow of a capture; thread `self` through as owned context
        // instead.
        let retry = (|mut sync: Self| {
            let shutdown = shutdown.clone();
            async move {
                let result = sync
                    .sync(shutdown)
                    .await
                    .and_then(|()| Err(anyhow::anyhow!("unexpected end of stream")));
                (sync, result)
            }
        })
        .retry(retry::constant(RECONNECT_DELAY, None))
        .context(self)
        .notify(|err, _| {
            warn!(
                err,
                target: LOG_TARGET,
                "Proof sync failed, retrying",
                retry.delay_ms = RECONNECT_DELAY.as_millis() as u64
            );
        });

        tokio::select! {
            (_, result) = retry => result,
            () = shutdown.cancelled() => Ok(()),
        }
    }

    async fn sync(&mut self, shutdown: CancellationToken) -> anyhow::Result<()> {
        // Subscribe from next proven tip.
        let starting_block = self.state.proven_tip().child();
        info!(
            target: LOG_TARGET,
            "Subscribing to block proof stream",
            block.from = starting_block
        );
        let mut client = self.source_rpc.clone();
        let mut stream = client
            .proof_subscription(ProofSubscriptionRequest { block_from: starting_block.as_u32() })
            .await?
            .into_inner();

        let mut expected = starting_block;
        let mut committed_tip_rx = self.state.subscribe_committed_tip();
        loop {
            let result = tokio::select! {
                () = shutdown.cancelled() => return Ok(()),
                result = stream.next() => result,
            };
            let Some(result) = result else {
                return Ok(());
            };
            let event = result?;
            let block_num = BlockNumber::from(event.block_num);

            anyhow::ensure!(
                block_num == expected,
                "upstream sent out-of-sequence proof: expected block {expected}, got {block_num}",
            );

            // Ensure the block is committed before applying its proof so that proven tip never
            // exceeds committed tip.
            tokio::select! {
                () = shutdown.cancelled() => return Ok(()),
                result = committed_tip_rx.wait_for(|committed_tip| *committed_tip >= block_num) => {
                    result.context("committed tip channel closed")?;
                },
            }

            let proof: ExecutionProof = event
                .proof
                .ok_or_else(|| anyhow::anyhow!("upstream proof event is missing its proof"))?
                .try_into()
                .context("failed to decode proof from upstream")?;
            self.writer.apply_proof(block_num, proof.to_bytes()).await?;

            expected = expected.child();
        }
    }
}

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
