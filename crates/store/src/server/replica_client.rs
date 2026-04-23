use std::sync::Arc;
use std::time::Duration;

use miden_node_proto::generated::store::{SubscribeBlocksRequest, store_replica_client};
use miden_protocol::block::SignedBlock;
use miden_protocol::utils::serde::Deserializable;
use tokio_stream::StreamExt as _;
use tracing::{error, info, warn};
use url::Url;

use crate::state::{Finality, State};

const RECONNECT_DELAY: Duration = Duration::from_secs(5);

/// Spawns the replica sync task as a background [`tokio::task::JoinHandle`].
///
/// The task connects to `upstream_url`, subscribes to the `StoreReplica.SubscribeBlocks` stream
/// starting from the local chain tip, and applies each incoming block to `state`. On any error
/// (including `DATA_LOSS` lag) it waits [`RECONNECT_DELAY`] and reconnects from the new local tip.
pub fn spawn(state: Arc<State>, upstream_url: Url) -> tokio::task::JoinHandle<anyhow::Result<()>> {
    tokio::spawn(run(state, upstream_url))
}

async fn run(state: Arc<State>, upstream_url: Url) -> anyhow::Result<()> {
    loop {
        match sync(&state, &upstream_url).await {
            Ok(()) => {
                warn!("Upstream block stream ended unexpectedly; reconnecting");
            },
            Err(err) => {
                error!(%err, "Upstream sync error; reconnecting in {RECONNECT_DELAY:?}");
            },
        }
        tokio::time::sleep(RECONNECT_DELAY).await;
    }
}

/// Connects to the upstream store, subscribes to blocks starting from the current local tip + 1,
/// and applies them one by one. Returns when the stream ends or on any error.
async fn sync(state: &State, upstream_url: &Url) -> anyhow::Result<()> {
    let local_tip = state.chain_tip(Finality::Committed).await;
    // Subscribe from the next block we don't yet have.
    let from_block_number = local_tip.as_u32().saturating_add(1);

    info!(from_block_number, %upstream_url, "Connecting to upstream store");

    // Establish the gRPC streaming client.
    let endpoint = tonic::transport::Channel::from_shared(upstream_url.to_string())?;
    let channel = endpoint.connect().await?;
    let mut client = store_replica_client::StoreReplicaClient::new(channel);

    // Subscribe to block events from the upstream store.
    let mut stream = client
        .subscribe_blocks(SubscribeBlocksRequest { from_block_number })
        .await?
        .into_inner();

    // Process block events from the upstream store.
    while let Some(result) = stream.next().await {
        // DATA_LOSS (lagged) and other gRPC errors surface here.
        let event = result?;
        let block = SignedBlock::read_from_bytes(&event.block)
            .map_err(|e| anyhow::anyhow!("failed to deserialize block from upstream: {e}"))?;

        let block_num = block.header().block_num();
        state.apply_block(block, None).await?;
        info!(block_num = block_num.as_u32(), "Applied block from upstream");
    }

    Ok(())
}
