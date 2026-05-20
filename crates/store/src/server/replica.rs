use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use miden_node_proto::generated::replica::{
    BlockProof,
    BlockSubscriptionRequest,
    ProofSubscriptionRequest,
    SignedBlock,
    api_server,
};
use miden_node_utils::ErrorReport;
use miden_protocol::block::BlockNumber;
use pin_project::pin_project;
use tokio::sync::{OwnedSemaphorePermit, mpsc, watch};
use tokio_stream::Stream;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use crate::server::api::StoreApi;
use crate::state::{BlockCache, ProofCache, State};

// GUARDED STREAM
// ================================================================================================

/// Wraps a stream and holds a semaphore permit for its lifetime, releasing it on drop.
#[pin_project]
struct GuardedStream<S: Stream> {
    #[pin]
    inner: S,
    _permit: OwnedSemaphorePermit,
}

impl<S: Stream> Stream for GuardedStream<S> {
    type Item = S::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.project().inner.poll_next(cx)
    }
}

// REPLICA API
// ================================================================================================

#[tonic::async_trait]
impl api_server::Api for StoreApi {
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
    /// Subscribes to the committed-tip watch channel and maintains a sequential counter. On each
    /// tip advance it emits all blocks from the current position up to the new tip, falling back to
    /// the block store for any entry not in the in-memory cache. The stream closes only when the
    /// client disconnects or the server shuts down.
    async fn block_subscription(
        &self,
        request: Request<BlockSubscriptionRequest>,
    ) -> Result<Response<Self::BlockSubscriptionStream>, Status> {
        let permit = Arc::clone(&self.block_subscription_semaphore)
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("maximum block subscriptions reached"))?;

        let from = BlockNumber::from(request.into_inner().block_from);

        let stream = build_block_stream(
            from,
            self.block_cache.clone(),
            self.committed_tip_rx.clone(),
            Arc::clone(&self.state),
        );
        Ok(Response::new(Box::pin(GuardedStream { inner: stream, _permit: permit })))
    }

    /// Streams block proofs to a replica starting from `from_block_number`.
    ///
    /// Uses the same watch-channel approach as [`Self::block_subscription`]: waits for the
    /// proven-in-sequence tip to advance, then emits all proofs from the current position up to
    /// the new tip, falling back to the block store for cache misses.
    async fn proof_subscription(
        &self,
        request: Request<ProofSubscriptionRequest>,
    ) -> Result<Response<Self::ProofSubscriptionStream>, Status> {
        let permit = Arc::clone(&self.proof_subscription_semaphore)
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("maximum proof subscriptions reached"))?;

        let from = BlockNumber::from(request.into_inner().block_from);

        let stream = build_proof_stream(
            from,
            self.proof_cache.clone(),
            self.proven_tip_rx.clone(),
            Arc::clone(&self.state),
        );
        Ok(Response::new(Box::pin(GuardedStream { inner: stream, _permit: permit })))
    }
}

// STREAM BUILDERS
// ================================================================================================

/// Spawns the block-stream task and returns its output as a [`ReceiverStream`].
fn build_block_stream(
    from: BlockNumber,
    cache: BlockCache,
    tip_rx: watch::Receiver<BlockNumber>,
    state: Arc<State>,
) -> impl Stream<Item = Result<SignedBlock, Status>> + Send + 'static {
    let (tx, rx) = mpsc::channel(32);
    tokio::spawn(async move {
        if let Err(status) = run_block_stream(from, cache, tip_rx, state, &tx).await {
            // Error indicates client disconnected, which is not an error on our side.
            let _ = tx.send(Err(status)).await;
        }
    });
    ReceiverStream::new(rx)
}

/// Spawns the proof-stream task and returns its output as a [`ReceiverStream`].
fn build_proof_stream(
    from: BlockNumber,
    cache: ProofCache,
    tip_rx: watch::Receiver<BlockNumber>,
    state: Arc<State>,
) -> impl Stream<Item = Result<BlockProof, Status>> + Send + 'static {
    let (tx, rx) = mpsc::channel(32);
    tokio::spawn(async move {
        if let Err(status) = run_proof_stream(from, cache, tip_rx, state, &tx).await {
            // Error indicates client disconnected, which is not an error on our side.
            let _ = tx.send(Err(status)).await;
        }
    });
    ReceiverStream::new(rx)
}

// STREAM TASKS
// ================================================================================================

/// Drives the block subscription loop until the client disconnects or the server shuts down.
///
/// On each committed-tip advance, emits all blocks from `next` to the new tip. Returns `Ok(())`
/// on a clean shutdown and `Err(status)` when a block cannot be loaded.
async fn run_block_stream(
    from: BlockNumber,
    cache: BlockCache,
    mut tip_rx: watch::Receiver<BlockNumber>,
    state: Arc<State>,
    tx: &mpsc::Sender<Result<SignedBlock, Status>>,
) -> Result<(), Status> {
    let mut next = from;
    loop {
        // Read tip.
        let tip = *tip_rx.borrow_and_update();
        while next <= tip {
            let bytes = fetch_block(next, &cache, &state).await?;
            if tx.send(Ok(SignedBlock { block: bytes })).await.is_err() {
                // Client disconnected.
                return Ok(());
            }
            next = next.child();
        }
        // Wait for tip change.
        if tip_rx.changed().await.is_err() {
            // Server shut down.
            return Ok(());
        }
    }
}

/// Drives the proof subscription loop until the client disconnects or the server shuts down.
///
/// On each proven-tip advance, emits all proofs from `next` to the new tip. Returns `Ok(())`
/// on a clean shutdown and `Err(status)` when a proof cannot be loaded.
async fn run_proof_stream(
    from: BlockNumber,
    cache: ProofCache,
    mut tip_rx: watch::Receiver<BlockNumber>,
    state: Arc<State>,
    tx: &mpsc::Sender<Result<BlockProof, Status>>,
) -> Result<(), Status> {
    let mut next = from;
    loop {
        // Read tip.
        let tip = *tip_rx.borrow_and_update();
        while next <= tip {
            let proof = fetch_proof(next, &cache, &state).await?;
            if tx.send(Ok(BlockProof { block_num: next.as_u32(), proof })).await.is_err() {
                // Client disconnected.
                return Ok(());
            }
            next = next.child();
        }
        // Wait for tip change.
        if tip_rx.changed().await.is_err() {
            // Server shut down.
            return Ok(());
        }
    }
}

// FETCH HELPERS
// ================================================================================================

/// Returns the raw bytes for `block_num`, checking the cache before falling back to disk.
async fn fetch_block(
    block_num: BlockNumber,
    cache: &BlockCache,
    state: &State,
) -> Result<Vec<u8>, Status> {
    if let Some(entry) = cache.get(&block_num) {
        return Ok(entry.block_bytes().to_vec());
    }
    state
        .load_block(block_num)
        .await
        .map_err(|e| {
            Status::internal(format!("failed to load block {block_num}: {}", e.as_report()))
        })?
        .ok_or_else(|| Status::not_found(format!("block {block_num} not found")))
}

/// Returns the raw proof bytes for `block_num`, checking the cache before falling back to disk.
async fn fetch_proof(
    block_num: BlockNumber,
    cache: &ProofCache,
    state: &State,
) -> Result<Vec<u8>, Status> {
    if let Some(entry) = cache.get(&block_num) {
        return Ok(entry.proof_bytes().to_vec());
    }
    state
        .load_proof(block_num)
        .await
        .map_err(|e| {
            Status::internal(format!(
                "failed to load proof for block {block_num}: {}",
                e.as_report()
            ))
        })?
        .ok_or_else(|| Status::not_found(format!("proof for block {block_num} not found")))
}
