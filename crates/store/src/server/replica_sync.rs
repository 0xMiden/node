use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use miden_crypto::utils::Deserializable;
use miden_node_proto::generated::store::{
    BlockSubscriptionRequest,
    ProofSubscriptionRequest,
    store_replica_client,
};
use miden_protocol::block::{BlockNumber, SignedBlock};
use tokio::sync::broadcast;
use tokio_stream::StreamExt;
use tracing::{info, instrument, warn};
use url::Url;

use crate::COMPONENT;
use crate::errors::{ApplyBlockError, InvalidBlockError};
use crate::proven_tip::ProvenTipWriter;
use crate::server::proof_scheduler::ProofNotification;
use crate::state::{Finality, State};

pub(crate) const RECONNECT_DELAY: Duration = Duration::from_secs(5);

// REPLICA SYNC
// ================================================================================================

/// Shared reconnect-loop scaffolding for replica client types.
///
/// Implementors provide a [`SYNC_KIND`](ReplicaSync::SYNC_KIND) label (used in log messages) and a
/// [`sync`](ReplicaSync::sync) method that connects to the upstream, streams data, and returns when
/// the stream ends or an error occurs. The default [`run`](ReplicaSync::run) and
/// [`spawn`](ReplicaSync::spawn) methods wrap that in an infinite reconnect loop.
#[async_trait]
pub(crate) trait ReplicaSync: Sized + Send + Sync + 'static {
    /// Short label used in log messages, e.g. `"Block"` or `"Proof"`.
    const SYNC_KIND: &'static str;

    /// Connects to the upstream and processes the stream until it ends or errors.
    async fn sync(&self) -> anyhow::Result<()>;

    /// Runs [`sync`](Self::sync) in an infinite loop, sleeping [`RECONNECT_DELAY`] on failure.
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
                "{} sync failed, retrying",
                Self::SYNC_KIND
            );
            tokio::time::sleep(RECONNECT_DELAY).await;
        }
    }

    /// Spawns [`run`](Self::run) as a Tokio task.
    fn spawn(self) -> tokio::task::JoinHandle<anyhow::Result<()>> {
        tokio::spawn(self.run())
    }
}

// BLOCK REPLICA SYNC
// ================================================================================================

/// Subscribes to blocks from an upstream store and applies them locally.
pub struct BlockReplicaSync {
    state: Arc<State>,
    upstream_url: Url,
}

impl BlockReplicaSync {
    pub fn new(state: Arc<State>, upstream_url: Url) -> Self {
        Self { state, upstream_url }
    }
}

#[async_trait]
impl ReplicaSync for BlockReplicaSync {
    const SYNC_KIND: &'static str = "Block";

    async fn sync(&self) -> anyhow::Result<()> {
        // Determine which block to start streaming from based on the chain tip.
        let block_from = self.state.chain_tip(Finality::Committed).await.child().as_u32();
        info!(block_from, upstream_url = %self.upstream_url, "Connecting to upstream store for blocks");

        // Connect to the upstream store and create a block subscription stream.
        let channel = tonic::transport::Channel::from_shared(self.upstream_url.to_string())?
            .connect()
            .await?;
        let mut client = store_replica_client::StoreReplicaClient::new(channel);
        let mut stream = client
            .block_subscription(BlockSubscriptionRequest { block_from })
            .await?
            .into_inner();

        // Process each block event from the stream.
        while let Some(result) = stream.next().await {
            let event = result?;
            let block = SignedBlock::read_from_bytes(&event.block)
                .context("failed to deserialize block from upstream")?;
            match self.state.apply_block(block, None).await {
                Ok(()) => {},
                Err(ApplyBlockError::InvalidBlockError(
                    InvalidBlockError::NewBlockInvalidBlockNum { expected, submitted },
                )) if submitted < expected => {
                    warn!(
                        block_num = submitted.as_u32(),
                        "Skipping already-applied block from upstream"
                    );
                },
                Err(err) => return Err(err.into()),
            }
        }

        Ok(())
    }
}

// PROOF REPLICA SYNC
// ================================================================================================

/// Subscribes to proofs from an upstream store and applies them locally.
pub struct ProofReplicaSync {
    state: Arc<State>,
    upstream_url: Url,
    proven_tip: ProvenTipWriter,
    proof_sender: broadcast::Sender<ProofNotification>,
}

impl ProofReplicaSync {
    pub fn new(
        state: Arc<State>,
        upstream_url: Url,
        proven_tip: ProvenTipWriter,
        proof_sender: broadcast::Sender<ProofNotification>,
    ) -> Self {
        Self {
            state,
            upstream_url,
            proven_tip,
            proof_sender,
        }
    }
}

#[async_trait]
impl ReplicaSync for ProofReplicaSync {
    const SYNC_KIND: &'static str = "Proof";

    async fn sync(&self) -> anyhow::Result<()> {
        // Determine which block to start streaming from based on the chain tip.
        let block_from = self.state.chain_tip(Finality::Proven).await.as_u32().saturating_add(1);
        info!(block_from, upstream_url = %self.upstream_url, "Connecting to upstream store for proofs");

        // Connect to the upstream store and create a proof subscription stream.
        let channel = tonic::transport::Channel::from_shared(self.upstream_url.to_string())?
            .connect()
            .await?;
        let mut client = store_replica_client::StoreReplicaClient::new(channel);
        let mut stream = client
            .proof_subscription(ProofSubscriptionRequest { block_from })
            .await?
            .into_inner();

        // Process each block event from the stream.
        while let Some(result) = stream.next().await {
            let event = result?;
            let block_num = BlockNumber::from(event.block_num);
            self.apply_proof(block_num, event.proof).await?;
        }

        Ok(())
    }
}

impl ProofReplicaSync {
    #[instrument(target = COMPONENT, skip_all, err, fields(block.number = block_num.as_u32()))]
    async fn apply_proof(&self, block_num: BlockNumber, proof: Vec<u8>) -> anyhow::Result<()> {
        self.state.block_store().save_proof(block_num, &proof).await?;
        let tip = self.state.db().mark_proven_and_advance_sequence(block_num).await?;
        self.proven_tip.advance(tip);

        // Blocks are broadcast by apply_block internally; proofs have no equivalent path so
        // we broadcast here to forward to any downstream replicas.
        let _ = self.proof_sender.send(ProofNotification { block_num, proof_bytes: proof });
        Ok(())
    }
}
