use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use miden_node_proto::clients::RpcClient;
use miden_node_proto::generated::rpc::{BlockSubscriptionRequest, ProofSubscriptionRequest};
use miden_node_store::state::{Finality, State};
use miden_node_utils::tasks::Tasks;
use miden_protocol::block::{BlockNumber, SignedBlock};
use miden_protocol::utils::serde::Deserializable;
use tokio_stream::StreamExt;
use tracing::{info, warn};

pub(crate) const RECONNECT_DELAY: Duration = Duration::from_secs(5);

// RPC SYNC
// ================================================================================================

/// Synchronizes local state from an upstream RPC service.
pub struct RpcSync {
    pub state: Arc<State>,
    pub source_rpc: RpcClient,
}

impl RpcSync {
    /// Spawns the block and proof synchronization loops as a supervised Tokio task.
    pub fn spawn(self) -> tokio::task::JoinHandle<anyhow::Result<()>> {
        tokio::spawn(async move {
            let mut tasks = Tasks::new();
            let block_sync = BlockSync {
                state: Arc::clone(&self.state),
                source_rpc: self.source_rpc.clone(),
            };
            let proof_sync = ProofSync {
                state: self.state,
                source_rpc: self.source_rpc,
            };

            tasks.spawn("block-sync", block_sync.run());
            tasks.spawn("proof-sync", proof_sync.run());

            tasks.join_next_as_error().await
        })
    }
}

// SYNC LOOP
// ================================================================================================

struct BlockSync {
    state: Arc<State>,
    source_rpc: RpcClient,
}

struct ProofSync {
    state: Arc<State>,
    source_rpc: RpcClient,
}

impl BlockSync {
    async fn run(self) -> anyhow::Result<()> {
        loop {
            let err = self
                .sync()
                .await
                .and_then(|_| Err::<(), _>(anyhow::anyhow!("unexpected end of stream")))
                .unwrap_err();
            warn!(
                err = %format!("{err:#}"),
                retry.delay = %RECONNECT_DELAY.as_secs(),
                "Block sync failed, retrying",
            );
            tokio::time::sleep(RECONNECT_DELAY).await;
        }
    }

    async fn sync(&self) -> anyhow::Result<()> {
        let block_from = self.state.chain_tip(Finality::Committed).await.child().as_u32();
        info!(block_from, "Connecting to upstream RPC for blocks");

        let mut client = self.source_rpc.clone();
        let mut stream = client
            .block_subscription(BlockSubscriptionRequest { block_from })
            .await?
            .into_inner();

        while let Some(result) = stream.next().await {
            let event = result?;
            let block = SignedBlock::read_from_bytes(&event.block)
                .context("failed to deserialize block from upstream")?;
            self.state.apply_block(block).await?;
        }

        Ok(())
    }
}

impl ProofSync {
    async fn run(self) -> anyhow::Result<()> {
        loop {
            let err = self
                .sync()
                .await
                .and_then(|_| Err::<(), _>(anyhow::anyhow!("unexpected end of stream")))
                .unwrap_err();
            warn!(
                err = %format!("{err:#}"),
                retry.delay = %RECONNECT_DELAY.as_secs(),
                "Proof sync failed, retrying",
            );
            tokio::time::sleep(RECONNECT_DELAY).await;
        }
    }

    async fn sync(&self) -> anyhow::Result<()> {
        let block_from = self.state.chain_tip(Finality::Proven).await.as_u32().saturating_add(1);
        info!(block_from, "Connecting to upstream RPC for proofs");

        let mut client = self.source_rpc.clone();
        let mut stream = client
            .proof_subscription(ProofSubscriptionRequest { block_from })
            .await?
            .into_inner();

        while let Some(result) = stream.next().await {
            let event = result?;
            let block_num = BlockNumber::from(event.block_num);
            self.state.apply_proof(block_num, event.proof).await?;
        }

        Ok(())
    }
}
