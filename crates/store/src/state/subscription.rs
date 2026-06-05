use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use miden_protocol::block::BlockNumber;
use thiserror::Error;
use tokio::sync::{mpsc, watch};
use tokio_stream::Stream;
use tokio_stream::wrappers::ReceiverStream;

use super::{BlockCache, ProofCache, State};
use crate::errors::DatabaseError;

/// Buffered messages per subscriber before back-pressure begins.
const SUBSCRIBER_CHANNEL_CAPACITY: usize = 32;
/// Number of blocks beyond the smallest gap observed so far before a subscriber is disconnected.
const MAX_SLOW_GAP: u32 = 100;
/// Safety-net timeout for a single send when the client has stalled.
const SEND_TIMEOUT: Duration = Duration::from_secs(10);

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
        Box::pin(build_stream(
            from,
            self.subscribe_committed_tip(),
            BlockSource {
                cache: self.block_cache.clone(),
                state: Arc::clone(self),
            },
        ))
    }

    /// Streams block proofs starting from `from`, replaying historical proofs first and then
    /// following newly proven blocks.
    pub fn proof_subscription(self: &Arc<Self>, from: BlockNumber) -> ProofSubscriptionStream {
        Box::pin(build_stream(
            from,
            self.subscribe_proven_tip(),
            ProofSource {
                cache: self.proof_cache.clone(),
                state: Arc::clone(self),
            },
        ))
    }
}

// SUBSCRIPTION SOURCE
// ================================================================================================

trait SubscriptionSource: Send + Sync + 'static {
    type Event: Send + 'static;

    fn fetch(
        &self,
        block_num: BlockNumber,
    ) -> impl Future<Output = Result<Vec<u8>, StateSubscriptionError>> + Send + '_;

    fn build_event(&self, block_num: BlockNumber, data: Vec<u8>, tip: BlockNumber) -> Self::Event;
}

struct BlockSource {
    cache: BlockCache,
    state: Arc<State>,
}

impl SubscriptionSource for BlockSource {
    type Event = BlockSubscriptionEvent;

    async fn fetch(&self, block_num: BlockNumber) -> Result<Vec<u8>, StateSubscriptionError> {
        if let Some(entry) = self.cache.get(block_num) {
            return Ok(entry.block_bytes().to_vec());
        }
        self.state
            .load_block(block_num)
            .await
            .map_err(|source| StateSubscriptionError::BlockLoad { block_num, source })?
            .ok_or(StateSubscriptionError::BlockNotFound(block_num))
    }

    fn build_event(
        &self,
        _block_num: BlockNumber,
        block: Vec<u8>,
        committed_chain_tip: BlockNumber,
    ) -> BlockSubscriptionEvent {
        BlockSubscriptionEvent { block, committed_chain_tip }
    }
}

struct ProofSource {
    cache: ProofCache,
    state: Arc<State>,
}

impl SubscriptionSource for ProofSource {
    type Event = ProofSubscriptionEvent;

    async fn fetch(&self, block_num: BlockNumber) -> Result<Vec<u8>, StateSubscriptionError> {
        if let Some(entry) = self.cache.get(block_num) {
            return Ok(entry.proof_bytes().to_vec());
        }
        self.state
            .load_proof(block_num)
            .await
            .map_err(|source| StateSubscriptionError::ProofLoad { block_num, source })?
            .ok_or(StateSubscriptionError::ProofNotFound(block_num))
    }

    fn build_event(
        &self,
        block_num: BlockNumber,
        proof: Vec<u8>,
        proven_chain_tip: BlockNumber,
    ) -> ProofSubscriptionEvent {
        ProofSubscriptionEvent { block_num, proof, proven_chain_tip }
    }
}

// STREAM
// ================================================================================================

fn build_stream<S: SubscriptionSource>(
    from: BlockNumber,
    tip_rx: watch::Receiver<BlockNumber>,
    source: S,
) -> impl Stream<Item = Result<S::Event, StateSubscriptionError>> + Send + 'static {
    let (tx, rx) = mpsc::channel(SUBSCRIBER_CHANNEL_CAPACITY);
    tokio::spawn(async move {
        if let Err(err) = run_stream(from, tip_rx, &tx, source).await {
            let _ = tx.send(Err(err)).await;
        }
    });
    ReceiverStream::new(rx)
}

/// Drives a generic subscription stream, replaying history then following live tip advances.
///
/// Calls [`SubscriptionSource::fetch`] for each block in sequence starting from `from`, builds an
/// event with [`SubscriptionSource::build_event`], and sends it to `tx`. Disconnects the
/// subscriber with [`StateSubscriptionError::TooSlow`] if the gap between the tip and the next
/// block to send exceeds the minimum gap ever observed plus [`MAX_SLOW_GAP`], or if a single send
/// blocks for longer than [`SEND_TIMEOUT`] (safety net for a stalled client).
async fn run_stream<S: SubscriptionSource>(
    from: BlockNumber,
    mut tip_rx: watch::Receiver<BlockNumber>,
    tx: &mpsc::Sender<Result<S::Event, StateSubscriptionError>>,
    source: S,
) -> Result<(), StateSubscriptionError> {
    let mut next = from;
    let mut min_gap = u32::MAX;
    loop {
        let mut tip = *tip_rx.borrow_and_update();
        while next <= tip {
            let gap = tip.as_u32() - next.as_u32();
            min_gap = min_gap.min(gap);
            if gap > min_gap + MAX_SLOW_GAP {
                return Err(StateSubscriptionError::TooSlow);
            }
            let data = source.fetch(next).await?;
            tip = *tip_rx.borrow_and_update();
            let permit = match tokio::time::timeout(SEND_TIMEOUT, tx.reserve()).await {
                Ok(Ok(permit)) => permit,
                Ok(Err(_)) => return Ok(()),
                Err(_) => return Err(StateSubscriptionError::TooSlow),
            };
            permit.send(Ok(source.build_event(next, data, tip)));
            next = next.child();
        }
        if tip_rx.changed().await.is_err() {
            return Ok(());
        }
    }
}
