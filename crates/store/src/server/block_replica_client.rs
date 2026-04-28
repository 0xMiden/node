use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use miden_node_proto::generated::store::{BlockSubscriptionRequest, store_replica_client};
use miden_protocol::block::SignedBlock;
use miden_protocol::utils::serde::Deserializable;
use tokio_stream::StreamExt as _;
use tracing::{info, warn};
use url::Url;

use crate::errors::{ApplyBlockError, InvalidBlockError};
use crate::state::{Finality, State};

const RECONNECT_DELAY: Duration = Duration::from_secs(5);

/// Subscribes to blocks from an upstream store and applies them locally.
pub struct BlockReplicaClient {
    state: Arc<State>,
    upstream_url: Url,
}

impl BlockReplicaClient {
    pub fn new(state: Arc<State>, upstream_url: Url) -> Self {
        Self { state, upstream_url }
    }

    pub fn spawn(self) -> tokio::task::JoinHandle<anyhow::Result<()>> {
        tokio::spawn(self.run())
    }

    async fn run(self) -> anyhow::Result<()> {
        loop {
            let err = self
                .sync()
                .await
                .and_then(|_| Err::<(), _>(anyhow::anyhow!("unexpected end of stream")))
                .unwrap_err();
            warn!(err=%format!("{err:#}"), retry.delay=%RECONNECT_DELAY.as_secs(), "Block sync failed, retrying");
            tokio::time::sleep(RECONNECT_DELAY).await;
        }
    }

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
