use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use miden_node_utils::DEFAULT_BLOCK_INTERVAL;
use miden_protocol::block::BlockNumber;
use thiserror::Error;
use tokio::sync::{mpsc, watch};
use tokio_stream::Stream;
use tokio_stream::wrappers::ReceiverStream;

use super::{BlockCache, ProofCache, State};
use crate::errors::DatabaseError;

/// Buffered messages per subscriber before back-pressure begins and slow-strike timeouts apply.
const SUBSCRIBER_CHANNEL_CAPACITY: usize = 32;
/// How long to wait for a subscriber to accept a message before counting a strike.
const SEND_TIMEOUT: Duration = DEFAULT_BLOCK_INTERVAL;
/// Number of consecutive send timeouts before a subscriber is considered too slow and disconnected.
const MAX_SLOW_STRIKES: u32 = 5;

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
    #[error("subscriber is too slow to keep up with the chain")]
    TooSlow,
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
    let (tx, rx) = mpsc::channel(SUBSCRIBER_CHANNEL_CAPACITY);
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
    let (tx, rx) = mpsc::channel(SUBSCRIBER_CHANNEL_CAPACITY);
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
    tip_rx: watch::Receiver<BlockNumber>,
    state: Arc<State>,
    tx: &mpsc::Sender<Result<BlockSubscriptionEvent, StateSubscriptionError>>,
) -> Result<(), StateSubscriptionError> {
    run_stream(
        from,
        tip_rx,
        tx,
        |block_num| {
            let cache = cache.clone();
            let state = Arc::clone(&state);
            async move { fetch_block(block_num, &cache, &state).await }
        },
        |_, block, committed_chain_tip| BlockSubscriptionEvent { block, committed_chain_tip },
    )
    .await
}

async fn run_proof_stream(
    from: BlockNumber,
    cache: ProofCache,
    tip_rx: watch::Receiver<BlockNumber>,
    state: Arc<State>,
    tx: &mpsc::Sender<Result<ProofSubscriptionEvent, StateSubscriptionError>>,
) -> Result<(), StateSubscriptionError> {
    run_stream(
        from,
        tip_rx,
        tx,
        |block_num| {
            let cache = cache.clone();
            let state = Arc::clone(&state);
            async move { fetch_proof(block_num, &cache, &state).await }
        },
        |block_num, proof, proven_chain_tip| ProofSubscriptionEvent {
            block_num,
            proof,
            proven_chain_tip,
        },
    )
    .await
}

/// Drives a generic subscription stream, replaying history then following live tip advances.
///
/// Calls `fetch` for each block in sequence starting from `from`, builds an event with
/// `build_event(block_num, data, tip)`, and sends it to `tx`. Disconnects the subscriber
/// with [`StateSubscriptionError::TooSlow`] if sending blocks for [`MAX_SLOW_STRIKES`]
/// consecutive [`SEND_TIMEOUT`] intervals.
async fn run_stream<E, F, Fut>(
    from: BlockNumber,
    mut tip_rx: watch::Receiver<BlockNumber>,
    tx: &mpsc::Sender<Result<E, StateSubscriptionError>>,
    fetch: F,
    build_event: impl Fn(BlockNumber, Vec<u8>, BlockNumber) -> E,
) -> Result<(), StateSubscriptionError>
where
    F: Fn(BlockNumber) -> Fut,
    Fut: Future<Output = Result<Vec<u8>, StateSubscriptionError>>,
{
    let mut next = from;
    let mut slow_strikes = 0u32;
    loop {
        let mut tip = *tip_rx.borrow_and_update();
        while next <= tip {
            let data = fetch(next).await?;
            tip = *tip_rx.borrow_and_update();
            let permit = loop {
                match tokio::time::timeout(SEND_TIMEOUT, tx.reserve()).await {
                    Ok(Ok(permit)) => {
                        slow_strikes = 0;
                        break permit;
                    },
                    Ok(Err(_)) => return Ok(()),
                    Err(_) => {
                        slow_strikes += 1;
                        if slow_strikes >= MAX_SLOW_STRIKES {
                            return Err(StateSubscriptionError::TooSlow);
                        }
                    },
                }
            };
            permit.send(Ok(build_event(next, data, tip)));
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
