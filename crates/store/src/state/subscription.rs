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
/// Safety-net timeout for a single send when the client has stalled.
const SEND_TIMEOUT: Duration = Duration::from_secs(10);
/// Maximum running block-gap allowed before a subscriber is disconnected.
const MAX_RUNNING_GAP: u32 = 100u32;

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
/// subscriber with [`StateSubscriptionError::TooSlow`] if a single send blocks for longer than [`SEND_TIMEOUT`]
/// which may occur only after the buffer has [`SUBSCRIBER_CHANNEL_CAPACITY`] blocks queued.
async fn run_stream<S: SubscriptionSource>(
    from: BlockNumber,
    mut tip_rx: watch::Receiver<BlockNumber>,
    tx: &mpsc::Sender<Result<S::Event, StateSubscriptionError>>,
    source: S,
) -> Result<(), StateSubscriptionError> {
    let mut next = from;
    let mut previous_gap = tip_rx.borrow().as_u32();
    let mut running_gap = 0u32;
    loop {
        let mut tip = *tip_rx.borrow_and_update();

        let current_gap = tip.saturating_sub(next.as_u32()).as_u32();
        (previous_gap, running_gap) =
            check_growing_gap(current_gap, previous_gap, running_gap)?;

        while next <= tip {
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

/// Tracks how many blocks a subscriber's gap to the tip has grown across consecutive checks.
///
/// Tracks a running total of how far a subscriber's gap to the tip has grown.
///
/// The total increases by the block-count delta each time the gap grows, and decreases by the
/// delta each time it shrinks (saturating at zero). Returns updated `(previous_gap, running_gap)`
/// on success, or [`StateSubscriptionError::TooSlow`] once the running total exceeds
/// [`MAX_RUNNING_GAP`].
fn check_growing_gap(
    current_gap: u32,
    previous_gap: u32,
    running_gap: u32,
) -> Result<(u32, u32), StateSubscriptionError> {
    let running_gap = if current_gap > previous_gap {
        running_gap + (current_gap - previous_gap)
    } else {
        running_gap.saturating_sub(previous_gap - current_gap)
    };
    if running_gap > MAX_RUNNING_GAP {
        return Err(StateSubscriptionError::TooSlow);
    }
    Ok((current_gap, running_gap))
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn run(gaps: &[u32]) -> Result<(), StateSubscriptionError> {
        let mut previous_gap = gaps.first().copied().unwrap_or(u32::MAX);
        let mut growth_run = 0u32;
        for &gap in gaps {
            (previous_gap, growth_run) =
                check_growing_gap(gap, previous_gap, growth_run)?;
        }
        Ok(())
    }

    #[test]
    fn stable_gap_does_not_accumulate() {
        // Gap stays constant — delta is always 0, growth_run never increments.
        assert!(run(&[5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5]).is_ok());
    }

    #[test]
    fn zero_gap_throughout_is_ok() {
        assert!(run(&[0, 0, 0, 0, 0]).is_ok());
    }

    #[test]
    fn shrinking_gap_reduces_accumulation() {
        // Accumulate close to the limit, then shrink — running total decreases, no error.
        assert!(run(&[10, 20, MAX_RUNNING_GAP - 1, 5]).is_ok());
    }

    #[test]
    fn starting_above_max_growth_is_ok() {
        assert!(run(&[MAX_RUNNING_GAP * 2]).is_ok());
    }

    #[test]
    fn exactly_max_growth_run_is_ok() {
        // A single jump of exactly MAX_RUNNING_GAP is the boundary — still ok.
        assert!(run(&[0, MAX_RUNNING_GAP]).is_ok());
    }

    #[test]
    fn exceeding_max_growth_run_returns_too_slow() {
        // One block past the limit triggers TooSlow, even in a single jump.
        assert!(matches!(run(&[0, MAX_RUNNING_GAP + 1]), Err(StateSubscriptionError::TooSlow)));
    }

    #[test]
    fn growth_spread_across_windows_accumulates() {
        // Many small growths that each stay below the limit still trigger TooSlow once they sum
        // past MAX_RUNNING_GAP.
        let step = MAX_RUNNING_GAP / 4;
        let gaps: Vec<u32> = (1..=6).map(|i| i * step).collect(); // total growth = 5 * step
        assert!(matches!(run(&gaps), Err(StateSubscriptionError::TooSlow)));
    }

    #[test]
    fn recovery_reduces_and_allows_fresh_accumulation() {
        // Grow close to the limit, recover most of the way, then grow again — still ok.
        let near_limit = MAX_RUNNING_GAP - 1;
        assert!(run(&[near_limit, 1, near_limit]).is_ok());
    }

    #[test]
    fn token_improvement_does_not_prevent_disconnection() {
        // A client that grows by a large amount then shrinks by just one block on each cycle
        // accumulates net growth and is eventually disconnected.
        let gaps: Vec<u32> = (0u32..MAX_RUNNING_GAP + 10).flat_map(|i| [50 + i, 49 + i]).collect();
        assert!(matches!(run(&gaps), Err(StateSubscriptionError::TooSlow)));
    }
}
