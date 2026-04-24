use std::sync::Arc;
use std::time::Duration;

use miden_node_proto::generated::store::{
    SubscribeBlocksRequest,
    SubscribeProofsRequest,
    store_replica_client,
};
use miden_protocol::block::{BlockNumber, SignedBlock};
use miden_protocol::utils::serde::Deserializable;
use tokio::sync::broadcast;
use tokio_stream::StreamExt as _;
use tracing::{info, instrument, warn};
use url::Url;

use crate::COMPONENT;
use crate::proven_tip::ProvenTipWriter;
use crate::server::proof_scheduler::ProofNotification;
use crate::state::{Finality, State};

const RECONNECT_DELAY: Duration = Duration::from_secs(5);

/// Spawns the replica sync task as a background [`tokio::task::JoinHandle`].
///
/// The task connects to `upstream_url` and concurrently syncs blocks and proofs. On any error
/// (including `DATA_LOSS` lag on either stream) it waits [`RECONNECT_DELAY`] and reconnects from
/// the current local tips.
pub fn spawn(
    state: Arc<State>,
    upstream_url: Url,
    proven_tip: ProvenTipWriter,
    proof_sender: broadcast::Sender<ProofNotification>,
) -> tokio::task::JoinHandle<anyhow::Result<()>> {
    tokio::spawn(run(state, upstream_url, proven_tip, proof_sender))
}

async fn run(
    state: Arc<State>,
    upstream_url: Url,
    proven_tip: ProvenTipWriter,
    proof_sender: broadcast::Sender<ProofNotification>,
) -> anyhow::Result<()> {
    loop {
        let result = tokio::try_join!(
            sync_blocks(&state, &upstream_url),
            sync_proofs(&state, &upstream_url, &proven_tip, &proof_sender),
        );
        if result.is_err() {
            warn!("Upstream sync error; reconnecting in {RECONNECT_DELAY:?}");
        } else {
            warn!("Upstream streams ended unexpectedly; reconnecting");
        }
        tokio::time::sleep(RECONNECT_DELAY).await;
    }
}

/// Subscribes to blocks from the upstream starting at local committed tip + 1, applying each one.
#[instrument(target = COMPONENT, skip_all, err)]
async fn sync_blocks(state: &State, upstream_url: &Url) -> anyhow::Result<()> {
    let from_block_number = state.chain_tip(Finality::Committed).await.as_u32().saturating_add(1);

    info!(from_block_number, %upstream_url, "Connecting to upstream store for blocks");

    let channel = tonic::transport::Channel::from_shared(upstream_url.to_string())?
        .connect()
        .await?;
    let mut client = store_replica_client::StoreReplicaClient::new(channel);

    let mut stream = client
        .subscribe_blocks(SubscribeBlocksRequest { from_block_number })
        .await?
        .into_inner();

    while let Some(result) = stream.next().await {
        let event = result?;
        let block = SignedBlock::read_from_bytes(&event.block)
            .map_err(|e| anyhow::anyhow!("failed to deserialize block from upstream: {e}"))?;

        let block_num = block.header().block_num();
        state.apply_block(block, None).await?;
        info!(block_num = block_num.as_u32(), "Applied block from upstream");
    }

    Ok(())
}

/// Subscribes to proofs from the upstream starting at local proven tip + 1, saving each one and
/// forwarding it to any downstream replica subscribers.
#[instrument(target = COMPONENT, skip_all, err)]
async fn sync_proofs(
    state: &State,
    upstream_url: &Url,
    proven_tip: &ProvenTipWriter,
    proof_sender: &broadcast::Sender<ProofNotification>,
) -> anyhow::Result<()> {
    let from_block_number = state.chain_tip(Finality::Proven).await.as_u32().saturating_add(1);

    info!(from_block_number, %upstream_url, "Connecting to upstream store for proofs");

    let channel = tonic::transport::Channel::from_shared(upstream_url.to_string())?
        .connect()
        .await?;
    let mut client = store_replica_client::StoreReplicaClient::new(channel);

    let mut stream = client
        .subscribe_proofs(SubscribeProofsRequest { from_block_number })
        .await?
        .into_inner();

    while let Some(result) = stream.next().await {
        let event = result?;
        let block_num = BlockNumber::from(event.block_num);

        state.block_store().save_proof(block_num, &event.proof).await?;
        let tip = state.db().mark_proven_and_advance_sequence(block_num).await?;
        proven_tip.advance(tip);

        // Blocks are broadcast by apply_block internally; proofs have no equivalent path so
        // we broadcast here to forward to any downstream replicas.
        let _ = proof_sender.send(ProofNotification { block_num, proof_bytes: event.proof });

        info!(block_num = block_num.as_u32(), "Applied proof from upstream");
    }

    Ok(())
}
