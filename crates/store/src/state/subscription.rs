use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use miden_node_utils::ErrorReport;
use miden_protocol::block::BlockNumber;
use thiserror::Error;
use tokio::sync::mpsc::error::SendTimeoutError;
use tokio::sync::mpsc::{self};
use tokio::sync::watch;
use tokio_stream::Stream;
use tokio_stream::wrappers::ReceiverStream;

use super::{BlockCache, ProofCache, State};
use crate::errors::DatabaseError;

/// Buffered messages per subscriber before back-pressure begins.
pub const SUBSCRIBER_CHANNEL_CAPACITY: usize = 32;
/// Safety-net timeout for a single send when the client has stalled.
const SEND_TIMEOUT: Duration = Duration::from_secs(10);
/// Maximum gap between tip and subscriber's requested starting block where the starting block is
/// greater than the tip.
const MAX_FUTURE_GAP: u32 = 100u32;

pub trait SubscriptionStream: Sized + Send {
    fn on_eos(&self, err: &StreamError);

    fn get_data(
        &self,
        block: BlockNumber,
    ) -> impl Future<Output = Result<Vec<u8>, DataError>> + Send + '_;

    fn stream(
        self,
        from: BlockNumber,
        mut chain_tip: watch::Receiver<BlockNumber>,
    ) -> impl Stream<Item = Result<StreamEvent, StreamError>> + Send + 'static
    where
        Self: 'static,
    {
        let (tx, rx) = tokio::sync::mpsc::channel(SUBSCRIBER_CHANNEL_CAPACITY);

        tokio::spawn(async move {
            let mut next = from.child();
            let mut gap_checker = StreamGapCheck::default();

            let err = loop {
                // Wait for the requisite data to become part of the chain.
                let Ok(tip) = chain_tip.wait_for(|tip| tip >= &next).await.map(|x| *x) else {
                    break StreamError::ServerShutdown;
                };

                // Ensure the client is keeping up with the chain.
                if gap_checker.check(next, tip).is_err() {
                    break StreamError::SlowSubscriber;
                }

                let Ok(data) = self.get_data(next).await.inspect_err(|err| {
                    tracing::error!(
                        block.number = %next,
                        message = %err.as_report(),
                        "failed to load data for stream"
                    );
                }) else {
                    break StreamError::Internal;
                };

                let event = StreamEvent { data, block: next, tip };
                if let Err(err) =
                    tx.send_timeout(Ok(event), SEND_TIMEOUT).await.map_err(|err| match err {
                        SendTimeoutError::Timeout(_) => StreamError::SlowSubscriber,
                        SendTimeoutError::Closed(_) => StreamError::ConnectionClosed,
                    })
                {
                    break err;
                }

                next = next.child();
            };

            self.on_eos(&err);
            let _ = tx.try_send(Err(err));
        });

        ReceiverStream::new(rx)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StreamError {
    #[error("server is shutting down")]
    ServerShutdown,
    #[error("client closed the stream")]
    ConnectionClosed,
    #[error("client is too slow to keep up with the chain")]
    SlowSubscriber,
    #[error("internal error")]
    Internal,
}

#[derive(Debug, thiserror::Error)]
pub enum DataError {
    #[error("data not found")]
    NotFound,
    #[error(transparent)]
    DatabaseError { source: DatabaseError },
}

pub struct StreamEvent {
    pub data: Vec<u8>,
    pub block: BlockNumber,
    pub tip: BlockNumber,
}

struct StreamGapCheck {
    previous_gap: u32,
    running_total: u32,
}

impl Default for StreamGapCheck {
    fn default() -> Self {
        Self { previous_gap: u32::MAX, running_total: 0 }
    }
}

impl StreamGapCheck {
    /// Maximum accumulated block-gap allowed before a subscriber is disconnected.
    const MAX_RUNNING_GAP: u32 = 100;

    fn check(&mut self, current: BlockNumber, tip: BlockNumber) -> Result<(), ()> {
        let gap = tip.saturating_sub(current.as_u32()).as_u32();

        self.running_total = if gap > self.previous_gap {
            self.running_total + (gap - self.previous_gap)
        } else {
            self.running_total.saturating_sub(self.previous_gap - gap)
        };

        self.previous_gap = gap;

        if self.running_total <= Self::MAX_RUNNING_GAP {
            Ok(())
        } else {
            Err(())
        }
    }
}

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

/// Error returned by a subscription stream.
///
/// Separates the two failure domains: [`TooSlow`](Self::TooSlow) is raised by the streaming
/// machinery itself when a subscriber falls too far behind, while [`Source`](Self::Source) wraps a
/// failure of the underlying [`SubscriptionSource`] to produce data.
#[derive(Debug, Error)]
pub enum SubscriptionStreamError<E> {
    #[error("subscriber is too slow to keep up with the chain")]
    TooSlow,
    #[error("subscriber's requested starting block is too far ahead of the chain tip")]
    TooFarAhead,
    #[error(transparent)]
    Source(#[from] E),
}

/// Error raised while loading a block for a block subscription.
#[derive(Debug, Error)]
pub enum BlockSubscriptionError {
    #[error("failed to load block {block_num}")]
    Load {
        block_num: BlockNumber,
        #[source]
        source: DatabaseError,
    },
    #[error("block {0} not found")]
    NotFound(BlockNumber),
}

/// Error raised while loading a proof for a proof subscription.
#[derive(Debug, Error)]
pub enum ProofSubscriptionError {
    #[error("failed to load proof for block {block_num}")]
    Load {
        block_num: BlockNumber,
        #[source]
        source: DatabaseError,
    },
    #[error("proof for block {0} not found")]
    NotFound(BlockNumber),
}

pub type BlockSubscriptionStream = Pin<
    Box<
        dyn Stream<
                Item = Result<
                    BlockSubscriptionEvent,
                    SubscriptionStreamError<BlockSubscriptionError>,
                >,
            > + Send,
    >,
>;

pub type ProofSubscriptionStream = Pin<
    Box<
        dyn Stream<
                Item = Result<
                    ProofSubscriptionEvent,
                    SubscriptionStreamError<ProofSubscriptionError>,
                >,
            > + Send,
    >,
>;

impl State {
    /// Streams committed blocks starting from `from`, replaying historical blocks first and then
    /// following live commits.
    pub fn block_subscription(self: &Arc<Self>, from: BlockNumber) -> BlockSubscriptionStream {
        Box::pin(run_stream(
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
        Box::pin(run_stream(
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

pub trait SubscriptionSource: Send + Sync + 'static {
    type Event: Send + 'static;
    type Error: std::error::Error + Send + 'static;

    fn fetch(
        &self,
        block_num: BlockNumber,
    ) -> impl Future<Output = Result<Vec<u8>, Self::Error>> + Send + '_;

    fn build_event(&self, block_num: BlockNumber, data: Vec<u8>, tip: BlockNumber) -> Self::Event;
}

struct BlockSource {
    cache: BlockCache,
    state: Arc<State>,
}

impl SubscriptionSource for BlockSource {
    type Event = BlockSubscriptionEvent;
    type Error = BlockSubscriptionError;

    async fn fetch(&self, block_num: BlockNumber) -> Result<Vec<u8>, BlockSubscriptionError> {
        if let Some(entry) = self.cache.get(block_num) {
            return Ok(entry.block_bytes().to_vec());
        }
        self.state
            .load_block(block_num)
            .await
            .map_err(|source| BlockSubscriptionError::Load { block_num, source })?
            .ok_or(BlockSubscriptionError::NotFound(block_num))
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
    type Error = ProofSubscriptionError;

    async fn fetch(&self, block_num: BlockNumber) -> Result<Vec<u8>, ProofSubscriptionError> {
        if let Some(entry) = self.cache.get(block_num) {
            return Ok(entry.proof_bytes().to_vec());
        }
        self.state
            .load_proof(block_num)
            .await
            .map_err(|source| ProofSubscriptionError::Load { block_num, source })?
            .ok_or(ProofSubscriptionError::NotFound(block_num))
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

/// Drives a generic subscription stream, replaying history then following live tip advances.
///
/// Calls [`SubscriptionSource::fetch`] for each block in sequence starting from `from`, builds an
/// event with [`SubscriptionSource::build_event`], and sends it to `tx`. Disconnects the
/// subscriber with [`SubscriptionStreamError::TooSlow`] if it falls too far behind the tip or if a
/// single send blocks for longer than [`SEND_TIMEOUT`], which may occur only after the buffer has
/// [`SUBSCRIBER_CHANNEL_CAPACITY`] blocks queued.
pub fn run_stream<S: SubscriptionSource>(
    from: BlockNumber,
    tip_rx: watch::Receiver<BlockNumber>,
    source: S,
) -> impl Stream<Item = Result<S::Event, SubscriptionStreamError<S::Error>>> + Send + 'static {
    let (tx, rx) = mpsc::channel(SUBSCRIBER_CHANNEL_CAPACITY);
    tokio::spawn(async move {
        if let Err(err) = run_stream_inner(from, tip_rx, &tx, source).await {
            let _ = tx.send(Err(err)).await;
        }
    });
    ReceiverStream::new(rx)
}

async fn run_stream_inner<S: SubscriptionSource>(
    from: BlockNumber,
    mut tip_rx: watch::Receiver<BlockNumber>,
    tx: &mpsc::Sender<Result<S::Event, SubscriptionStreamError<S::Error>>>,
    source: S,
) -> Result<(), SubscriptionStreamError<S::Error>> {
    let mut next = from;
    let tip = tip_rx.borrow().as_u32();
    if next.as_u32() > tip.saturating_add(MAX_FUTURE_GAP) {
        return Err(SubscriptionStreamError::TooFarAhead);
    }

    let mut gap_checker = StreamGapCheck::default();
    loop {
        let mut tip = *tip_rx.borrow_and_update();

        gap_checker.check(next, tip).map_err(|()| SubscriptionStreamError::TooSlow)?;

        while next <= tip {
            let data = source.fetch(next).await?;
            tip = *tip_rx.borrow_and_update();
            let permit = match tokio::time::timeout(SEND_TIMEOUT, tx.reserve()).await {
                Ok(Ok(permit)) => permit,
                Ok(Err(_)) => return Ok(()),
                Err(_) => return Err(SubscriptionStreamError::TooSlow),
            };
            permit.send(Ok(source.build_event(next, data, tip)));
            next = next.child();
        }
        // Wait for the tip to advance, but also terminate promptly if the subscriber has
        // disconnected (in case the tip is less than `next`).
        tokio::select! {
            changed = tip_rx.changed() => {
                if changed.is_err() {
                    return Ok(());
                }
            },
            () = tx.closed() => return Ok(()),
        }
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use tokio_stream::StreamExt;

    use super::*;

    /// Minimal [`SubscriptionSource`] for lifetime tests. `fetch` is never reached when `from` is
    /// ahead of the tip, so it just yields empty data.
    struct MockSource;

    impl SubscriptionSource for MockSource {
        type Event = ();
        type Error = BlockSubscriptionError;

        async fn fetch(&self, _block_num: BlockNumber) -> Result<Vec<u8>, Self::Error> {
            Ok(Vec::new())
        }

        fn build_event(&self, _block_num: BlockNumber, _data: Vec<u8>, _tip: BlockNumber) {}
    }

    /// A subscription whose `from` is ahead of the tip parks waiting for the tip to advance. When
    /// the subscriber disconnects (the returned stream is dropped), the detached task must
    /// terminate rather than leaking until the chain reaches `from`.
    #[tokio::test]
    async fn future_subscription_task_terminates_on_disconnect() {
        let (tip_tx, tip_rx) = watch::channel(BlockNumber::GENESIS);

        // `from` is far ahead of the tip, so the task never enters the send loop and parks on the
        // tip. The spawned task holds the only watch receiver.
        let stream = run_stream(BlockNumber::from(MAX_FUTURE_GAP - 1), tip_rx, MockSource);
        assert_eq!(tip_tx.receiver_count(), 1, "the spawned task should hold the tip receiver");

        // The client disconnects.
        drop(stream);

        // The task must observe the closed channel and drop its watch receiver. The tip never
        // advances, so a task that only waited on tip changes would hang here.
        tokio::time::timeout(Duration::from_secs(5), async {
            while tip_tx.receiver_count() > 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("subscription task must terminate after the subscriber disconnects");
    }

    #[tokio::test]
    async fn starting_block_exceeds_future_gap_returns_too_far_ahead() {
        let (_tip_tx, tip_rx) = watch::channel(BlockNumber::GENESIS);
        let from = BlockNumber::from(MAX_FUTURE_GAP + 1);
        let mut stream = run_stream(from, tip_rx, MockSource);

        let item = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("stream must yield promptly")
            .expect("stream must not end without an item");
        assert!(matches!(item, Err(SubscriptionStreamError::TooFarAhead)));
    }

    #[tokio::test]
    async fn starting_block_at_exact_future_gap_boundary_is_accepted() {
        let (tip_tx, tip_rx) = watch::channel(BlockNumber::GENESIS);
        // Exactly at the boundary: `from == tip + MAX_FUTURE_GAP` is NOT > tip + MAX_FUTURE_GAP, so
        // the subscription must be accepted.
        let from = BlockNumber::from(MAX_FUTURE_GAP);
        let mut stream = run_stream(from, tip_rx, MockSource);

        // Advance the tip to `from` so the task can produce an event rather than parking forever.
        tip_tx.send(from).unwrap();

        let item = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("stream must yield promptly")
            .expect("stream must not end without an item");
        assert!(matches!(item, Ok(())), "expected an event, not TooFarAhead: {item:?}");
    }

    fn run(gaps: &[u32]) -> Result<(), ()> {
        let mut gap_checker = StreamGapCheck::default();
        for &gap in gaps {
            gap_checker.check(BlockNumber::GENESIS, BlockNumber::from(gap))?;
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
        assert!(run(&[10, 20, StreamGapCheck::MAX_RUNNING_GAP - 1, 5]).is_ok());
    }

    #[test]
    fn starting_above_max_growth_is_ok() {
        assert!(run(&[StreamGapCheck::MAX_RUNNING_GAP * 2]).is_ok());
    }

    #[test]
    fn exactly_max_growth_run_is_ok() {
        // A single jump of exactly MAX_RUNNING_GAP is the boundary — still ok.
        assert!(run(&[0, StreamGapCheck::MAX_RUNNING_GAP]).is_ok());
    }

    #[test]
    fn exceeding_max_growth_run_returns_too_slow() {
        // One block past the limit triggers TooSlow, even in a single jump.
        assert!(matches!(run(&[0, StreamGapCheck::MAX_RUNNING_GAP + 1]), Err(())));
    }

    #[test]
    fn growth_spread_across_windows_accumulates() {
        // Many small growths that each stay below the limit still trigger TooSlow once they sum
        // past MAX_RUNNING_GAP.
        let step = StreamGapCheck::MAX_RUNNING_GAP / 4;
        let gaps: Vec<u32> = (1..=6).map(|i| i * step).collect(); // total growth = 5 * step
        assert!(matches!(run(&gaps), Err(())));
    }

    #[test]
    fn recovery_reduces_and_allows_fresh_accumulation() {
        // Grow close to the limit, recover most of the way, then grow again — still ok.
        let near_limit = StreamGapCheck::MAX_RUNNING_GAP - 1;
        assert!(run(&[near_limit, 1, near_limit]).is_ok());
    }

    #[test]
    fn token_improvement_does_not_prevent_disconnection() {
        // A client that grows by a large amount then shrinks by just one block on each cycle
        // accumulates net growth and is eventually disconnected.
        let gaps: Vec<u32> = (0u32..StreamGapCheck::MAX_RUNNING_GAP + 10)
            .flat_map(|i| [50 + i, 49 + i])
            .collect();
        assert!(matches!(run(&gaps), Err(())));
    }
}
