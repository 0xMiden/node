use std::pin::Pin;
use std::sync::Arc;

use miden_protocol::block::BlockNumber;
use thiserror::Error;
use tokio::sync::{mpsc, watch};
use tokio_stream::Stream;
use tokio_stream::wrappers::ReceiverStream;

use super::{BlockCache, ProofCache, State};
use crate::errors::DatabaseError;

// SUBSCRIPTION EVENTS
// ================================================================================================

#[derive(Debug)]
pub struct BlockSubscriptionEvent {
    pub block: Vec<u8>,
    pub committed_chain_tip: BlockNumber,
}

#[derive(Debug)]
pub struct ProofSubscriptionEvent {
    pub block_num: BlockNumber,
    pub proof: Vec<u8>,
    pub proven_chain_tip: BlockNumber,
}

#[derive(Debug, Error)]
pub enum StateSubscriptionError {
    #[error("failed to load block {block_num}")]
    BlockLoad {
        block_num: BlockNumber,
        #[source]
        source: DatabaseError,
    },
    #[error("block {0} not found")]
    BlockNotFound(BlockNumber),
    #[error("failed to load proof for block {block_num}")]
    ProofLoad {
        block_num: BlockNumber,
        #[source]
        source: DatabaseError,
    },
    #[error("proof for block {0} not found")]
    ProofNotFound(BlockNumber),
}

pub type BlockSubscriptionStream =
    Pin<Box<dyn Stream<Item = Result<BlockSubscriptionEvent, StateSubscriptionError>> + Send>>;

pub type ProofSubscriptionStream =
    Pin<Box<dyn Stream<Item = Result<ProofSubscriptionEvent, StateSubscriptionError>> + Send>>;

impl State {
    /// Streams committed blocks starting from `from`, replaying historical blocks first and then
    /// following live commits.
    pub fn block_subscription(self: &Arc<Self>, from: BlockNumber) -> BlockSubscriptionStream {
        Box::pin(build_block_stream(
            from,
            self.block_cache.clone(),
            self.subscribe_committed_tip(),
            Arc::clone(self),
        ))
    }

    /// Streams block proofs starting from `from`, replaying historical proofs first and then
    /// following newly proven blocks.
    pub fn proof_subscription(self: &Arc<Self>, from: BlockNumber) -> ProofSubscriptionStream {
        Box::pin(build_proof_stream(
            from,
            self.proof_cache.clone(),
            self.subscribe_proven_tip(),
            Arc::clone(self),
        ))
    }
}

// STREAM BUILDERS
// ================================================================================================

fn build_block_stream(
    from: BlockNumber,
    cache: BlockCache,
    tip_rx: watch::Receiver<BlockNumber>,
    state: Arc<State>,
) -> impl Stream<Item = Result<BlockSubscriptionEvent, StateSubscriptionError>> + Send + 'static {
    let (tx, rx) = mpsc::channel(32);
    tokio::spawn(async move {
        if let Err(err) = run_block_stream(from, cache, tip_rx, state, &tx).await {
            let _ = tx.send(Err(err)).await;
        }
    });
    ReceiverStream::new(rx)
}

fn build_proof_stream(
    from: BlockNumber,
    cache: ProofCache,
    tip_rx: watch::Receiver<BlockNumber>,
    state: Arc<State>,
) -> impl Stream<Item = Result<ProofSubscriptionEvent, StateSubscriptionError>> + Send + 'static {
    let (tx, rx) = mpsc::channel(32);
    tokio::spawn(async move {
        if let Err(err) = run_proof_stream(from, cache, tip_rx, state, &tx).await {
            let _ = tx.send(Err(err)).await;
        }
    });
    ReceiverStream::new(rx)
}

// STREAM TASKS
// ================================================================================================

async fn run_block_stream(
    from: BlockNumber,
    cache: BlockCache,
    mut tip_rx: watch::Receiver<BlockNumber>,
    state: Arc<State>,
    tx: &mpsc::Sender<Result<BlockSubscriptionEvent, StateSubscriptionError>>,
) -> Result<(), StateSubscriptionError> {
    let mut next = from;
    loop {
        let mut tip = *tip_rx.borrow_and_update();
        while next <= tip {
            let block = fetch_block(next, &cache, &state).await?;
            tip = *tip_rx.borrow_and_update();
            if tx
                .send(Ok(BlockSubscriptionEvent { block, committed_chain_tip: tip }))
                .await
                .is_err()
            {
                return Ok(());
            }
            next = next.child();
        }
        if tip_rx.changed().await.is_err() {
            return Ok(());
        }
    }
}

async fn run_proof_stream(
    from: BlockNumber,
    cache: ProofCache,
    mut tip_rx: watch::Receiver<BlockNumber>,
    state: Arc<State>,
    tx: &mpsc::Sender<Result<ProofSubscriptionEvent, StateSubscriptionError>>,
) -> Result<(), StateSubscriptionError> {
    let mut next = from;
    loop {
        let mut tip = *tip_rx.borrow_and_update();
        while next <= tip {
            let proof = fetch_proof(next, &cache, &state).await?;
            tip = *tip_rx.borrow_and_update();
            if tx
                .send(Ok(ProofSubscriptionEvent {
                    block_num: next,
                    proof,
                    proven_chain_tip: tip,
                }))
                .await
                .is_err()
            {
                return Ok(());
            }
            next = next.child();
        }
        if tip_rx.changed().await.is_err() {
            return Ok(());
        }
    }
}

async fn fetch_block(
    block_num: BlockNumber,
    cache: &BlockCache,
    state: &State,
) -> Result<Vec<u8>, StateSubscriptionError> {
    if let Some(entry) = cache.get(block_num) {
        return Ok(entry.block_bytes().to_vec());
    }
    state
        .load_block(block_num)
        .await
        .map_err(|source| StateSubscriptionError::BlockLoad { block_num, source })?
        .ok_or(StateSubscriptionError::BlockNotFound(block_num))
}

async fn fetch_proof(
    block_num: BlockNumber,
    cache: &ProofCache,
    state: &State,
) -> Result<Vec<u8>, StateSubscriptionError> {
    if let Some(entry) = cache.get(block_num) {
        return Ok(entry.proof_bytes().to_vec());
    }
    state
        .load_proof(block_num)
        .await
        .map_err(|source| StateSubscriptionError::ProofLoad { block_num, source })?
        .ok_or(StateSubscriptionError::ProofNotFound(block_num))
}
