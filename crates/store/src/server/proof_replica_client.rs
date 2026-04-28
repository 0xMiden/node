use std::sync::Arc;
use std::time::Duration;

use miden_node_proto::generated::store::{ProofSubscriptionRequest, store_replica_client};
use miden_protocol::block::BlockNumber;
use tokio::sync::broadcast;
use tokio_stream::StreamExt as _;
use tracing::{info, instrument, warn};
use url::Url;

use crate::COMPONENT;
use crate::proven_tip::ProvenTipWriter;
use crate::server::proof_scheduler::ProofNotification;
use crate::state::{Finality, State};

const RECONNECT_DELAY: Duration = Duration::from_secs(5);

/// Subscribes to proofs from an upstream store and applies them locally.
pub struct ProofReplicaClient {
    state: Arc<State>,
    upstream_url: Url,
    proven_tip: ProvenTipWriter,
    proof_sender: broadcast::Sender<ProofNotification>,
}

impl ProofReplicaClient {
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

    pub fn spawn(self) -> tokio::task::JoinHandle<anyhow::Result<()>> {
        tokio::spawn(self.run())
    }

    async fn run(self) -> anyhow::Result<()> {
        loop {
            if let Err(err) = self.sync().await {
                warn!(%err, "Proof sync error: {err}; reconnecting in {RECONNECT_DELAY:?}");
            } else {
                warn!("Proof stream ended unexpectedly; reconnecting");
            }
            tokio::time::sleep(RECONNECT_DELAY).await;
        }
    }

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
