use std::pin::Pin;
use std::sync::Arc;

use miden_node_proto::generated::store::{
    BlockProof,
    BlockSubscriptionRequest,
    ProofSubscriptionRequest,
    SignedBlock,
    store_replica_server,
};
use miden_protocol::block::BlockNumber;
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use tonic::{Request, Response, Status};

use crate::server::api::StoreApi;
use crate::server::proof_scheduler::ProofNotification;
use crate::state::{BlockNotification, Finality, State};

// STORE REPLICA API
// ================================================================================================

#[tonic::async_trait]
impl store_replica_server::StoreReplica for StoreApi {
    type BlockSubscriptionStream = Pin<
        Box<
            dyn tonic::codegen::tokio_stream::Stream<Item = Result<SignedBlock, Status>>
                + Send
                + 'static,
        >,
    >;

    type ProofSubscriptionStream = Pin<
        Box<
            dyn tonic::codegen::tokio_stream::Stream<Item = Result<BlockProof, Status>>
                + Send
                + 'static,
        >,
    >;

    /// Streams committed blocks to a replica starting from `from_block_number`.
    ///
    /// Two-phase approach:
    /// 1. Subscribe to the live broadcast channel BEFORE starting replay to avoid the race where a
    ///    block is committed between the end of replay and the start of live forwarding.
    /// 2. Replay historical blocks from the block store up to the chain tip at subscription time.
    /// 3. Drain any broadcast messages that arrived during replay, skipping already-replayed
    ///    blocks.
    /// 4. Forward live blocks from the broadcast channel indefinitely.
    ///
    /// On lag (replica falls more than 512 blocks behind), the stream closes with `DATA_LOSS` and
    /// the client should reconnect from its local tip.
    async fn block_subscription(
        &self,
        request: Request<BlockSubscriptionRequest>,
    ) -> Result<Response<Self::BlockSubscriptionStream>, Status> {
        let from = BlockNumber::from(request.into_inner().block_from);
        // chain_tip is async in this branch (acquires the inner RwLock).
        let chain_tip = self.state.chain_tip(Finality::Committed).await;

        // Subscribe to the live broadcast BEFORE replay to eliminate the gap race.
        let live_rx = self.block_sender.subscribe();

        let stream = build_block_stream(from, chain_tip, Arc::clone(&self.state), live_rx);
        Ok(Response::new(Box::pin(stream)))
    }

    /// Streams block proofs to a replica starting from `from_block_number`.
    ///
    /// Uses the same two-phase approach as [`Self::subscribe_blocks`]: subscribe first, replay
    /// historical proofs from disk, then forward live proof notifications.
    ///
    /// Blocks that are not yet proven are skipped during historical replay; the replica will
    /// receive their proofs via the live stream once proving completes.
    async fn proof_subscription(
        &self,
        request: Request<ProofSubscriptionRequest>,
    ) -> Result<Response<Self::ProofSubscriptionStream>, Status> {
        let from = BlockNumber::from(request.into_inner().block_from);
        let proven_tip = self.state.chain_tip(Finality::Proven).await;

        // Subscribe to the live broadcast BEFORE replay.
        let live_rx = self.proof_sender.subscribe();

        let stream = build_proof_stream(from, proven_tip, Arc::clone(&self.state), live_rx);
        Ok(Response::new(Box::pin(stream)))
    }
}

// STREAM BUILDERS
// ================================================================================================

/// Builds the two-phase block stream: historic replay followed by live broadcast forwarding.
fn build_block_stream(
    from: BlockNumber,
    chain_tip: BlockNumber,
    state: Arc<State>,
    live_rx: tokio::sync::broadcast::Receiver<BlockNotification>,
) -> impl tonic::codegen::tokio_stream::Stream<Item = Result<SignedBlock, Status>> + Send + 'static
{
    // Phase 1: replay historical blocks from the block store.
    let historical = tokio_stream::iter(from.as_u32()..=chain_tip.as_u32())
        .map(BlockNumber::from)
        .then(move |block_num| {
            let state = Arc::clone(&state);
            async move {
                let bytes = state
                    .load_block(block_num)
                    .await
                    .map_err(|e| {
                        Status::internal(format!(
                            "failed to load block {}: {e}",
                            block_num.as_u32()
                        ))
                    })?
                    .ok_or_else(|| {
                        Status::not_found(format!("block {} not found", block_num.as_u32()))
                    })?;
                Ok(SignedBlock { block: bytes })
            }
        });

    // Phase 2: forward live blocks, skipping any already covered by the replay.
    // filter_map in tokio_stream is synchronous.
    let live = BroadcastStream::new(live_rx).filter_map(move |result| match result {
        Ok(ref notification) if notification.block_num() > chain_tip => Some(Ok(SignedBlock {
            block: notification.block_bytes().to_vec(),
        })),
        Ok(_) => None, // already replayed
        Err(BroadcastStreamRecvError::Lagged(n)) => Some(Err(Status::data_loss(format!(
            "replica lagged by {n} blocks; reconnect from your local tip"
        )))),
    });

    historical.chain(live)
}

/// Builds the two-phase proof stream: historic replay from disk followed by live broadcast.
fn build_proof_stream(
    from: BlockNumber,
    proven_tip: BlockNumber,
    state: Arc<State>,
    live_rx: tokio::sync::broadcast::Receiver<ProofNotification>,
) -> impl tonic::codegen::tokio_stream::Stream<Item = Result<BlockProof, Status>> + Send + 'static {
    // Phase 1: replay existing proofs from disk for all proven blocks in the requested range.
    // Blocks without a proof file are skipped (not yet proven). Use then() + filter_map() since
    // load_proof is async but tokio_stream::StreamExt::filter_map is synchronous.
    let historical = tokio_stream::iter(from.as_u32()..=proven_tip.as_u32())
        .map(BlockNumber::from)
        .then(move |block_num| {
            let state = Arc::clone(&state);
            async move {
                match state.load_proof(block_num).await {
                    Ok(Some(bytes)) => Some(Ok(BlockProof {
                        block_num: block_num.as_u32(),
                        proof: bytes,
                    })),
                    Ok(None) => None, // not yet proven, skip
                    Err(e) => Some(Err(Status::internal(format!(
                        "failed to load proof for block {}: {e}",
                        block_num.as_u32()
                    )))),
                }
            }
        })
        .filter_map(|opt| opt);

    // Phase 2: forward live proof notifications, skipping those already covered by replay.
    let live = BroadcastStream::new(live_rx).filter_map(move |result| match result {
        Ok(notification) if notification.block_num() > proven_tip => Some(Ok(BlockProof {
            block_num: notification.block_num().as_u32(),
            proof: notification.proof_bytes().to_vec(),
        })),
        Ok(_) => None, // already replayed
        Err(BroadcastStreamRecvError::Lagged(n)) => Some(Err(Status::data_loss(format!(
            "replica lagged by {n} proofs; reconnect from your local tip"
        )))),
    });

    historical.chain(live)
}
