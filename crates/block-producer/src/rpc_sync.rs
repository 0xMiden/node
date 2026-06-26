use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use miden_node_proto::clients::RpcClient;
use miden_node_proto::generated::rpc::{BlockSubscriptionRequest, ProofSubscriptionRequest};
use miden_node_store::state::{Finality, State};
use miden_node_utils::retry::{self, Retryable};
use miden_node_utils::tasks::Tasks;
use miden_protocol::block::{BlockNumber, SignedBlock};
use miden_protocol::utils::serde::Deserializable;
use tokio_stream::StreamExt;
use tonic_health::ServingStatus;
use tonic_health::server::HealthReporter;
use tracing::{info, instrument, warn};

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
}

impl RpcReadiness {
    const SERVICE_NAME: &'static str = "rpc.Api";

    pub fn new(reporter: HealthReporter, threshold: u32) -> Self {
        Self { reporter, threshold }
    }

    /// Updates the RPC service health status based on the upstream/local tip gap.
    pub async fn update(&self, upstream_tip: BlockNumber, local_tip: BlockNumber) {
        let status = if upstream_tip.as_u32().saturating_sub(local_tip.as_u32()) <= self.threshold {
            ServingStatus::Serving
        } else {
            ServingStatus::NotServing
        };
        self.reporter.set_service_status(Self::SERVICE_NAME, status).await;
    }
}

// RPC SYNC
// ================================================================================================

/// Synchronizes local state from an upstream RPC service.
pub struct RpcSync {
    pub state: Arc<State>,
    pub source_rpc: RpcClient,
    pub readiness: RpcReadiness,
}

impl RpcSync {
    /// Runs the block and proof synchronization loops until one exits unexpectedly.
    pub async fn run(self) -> anyhow::Result<()> {
        let mut tasks = Tasks::new();
        let block_sync = BlockSync {
            state: Arc::clone(&self.state),
            source_rpc: self.source_rpc.clone(),
            readiness: self.readiness,
        };
        let proof_sync = ProofSync {
            state: self.state,
            source_rpc: self.source_rpc,
        };

        tasks.spawn("block-sync", block_sync.run());
        tasks.spawn("proof-sync", proof_sync.run());

        tasks.join_next_as_error().await
    }
}

// SYNC LOOP
// ================================================================================================

struct BlockSync {
    state: Arc<State>,
    source_rpc: RpcClient,
    readiness: RpcReadiness,
}

struct ProofSync {
    state: Arc<State>,
    source_rpc: RpcClient,
}

impl BlockSync {
    async fn run(self) -> anyhow::Result<()> {
        (|| async {
            self.sync()
                .await
                .and_then(|()| Err(anyhow::anyhow!("unexpected end of stream")))
        })
        .retry(retry::constant(RECONNECT_DELAY, None))
        .notify(|err, _| {
            warn!(
                err = %format!("{err:#}"),
                retry.delay = %RECONNECT_DELAY.as_secs(),
                "Block sync failed, retrying",
            );
        })
        .await
    }

    #[instrument(target = COMPONENT, skip_all, err)]
    async fn sync(&self) -> anyhow::Result<()> {
        let block_from = self.state.chain_tip(Finality::Committed).await.child().as_u32();
        info!(target: LOG_TARGET, block_from, "Connecting to upstream RPC for blocks");

        let mut client = self.source_rpc.clone();
        let mut stream = client
            .block_subscription(BlockSubscriptionRequest { block_from })
            .await?
            .into_inner();

        while let Some(result) = stream.next().await {
            let event = result?;
            let upstream_tip = BlockNumber::from(event.committed_chain_tip);
            let block = SignedBlock::read_from_bytes(&event.block)
                .context("failed to deserialize block from upstream")?;
            self.state.apply_block(block).await?;

            let local_tip = self.state.chain_tip(Finality::Committed).await;
            self.readiness.update(upstream_tip, local_tip).await;
        }

        Ok(())
    }
}

impl ProofSync {
    /// Synchronizes block proofs from an upstream RPC service.
    ///
    /// Proof sync is intentionally coupled to block sync via the committed tip: a proof is only applied
    /// once its block has been committed locally. This means proof sync can stall if block sync falls
    /// behind, but that is acceptable — there is no value in streaming proofs for blocks that have not
    /// yet been applied.
    async fn run(self) -> anyhow::Result<()> {
        (|| async {
            self.sync()
                .await
                .and_then(|()| Err(anyhow::anyhow!("unexpected end of stream")))
        })
        .retry(retry::constant(RECONNECT_DELAY, None))
        .notify(|err, _| {
            warn!(
                err = %format!("{err:#}"),
                retry.delay = %RECONNECT_DELAY.as_secs(),
                "Proof sync failed, retrying",
            );
        })
        .await
    }

    async fn sync(&self) -> anyhow::Result<()> {
        // Subscribe from next proven tip.
        let starting_block = self.state.chain_tip(Finality::Proven).await.child().as_u32();
        info!(target: LOG_TARGET, starting_block, "Connecting to upstream RPC for proofs");
        let mut client = self.source_rpc.clone();
        let mut stream = client
            .proof_subscription(ProofSubscriptionRequest { block_from: starting_block })
            .await?
            .into_inner();

        let mut committed_tip_rx = self.state.subscribe_committed_tip();
        while let Some(result) = stream.next().await {
            let event = result?;
            let proven_tip = BlockNumber::from(event.block_num);

            // Ensure the block is committed before applying its proof so that proven tip never
            // exceeds committed tip.
            committed_tip_rx
                .wait_for(|committed_tip| *committed_tip >= proven_tip)
                .await
                .context("committed tip channel closed")?;

            self.state.apply_proof(proven_tip, event.proof).await?;
        }

        Ok(())
    }
}
