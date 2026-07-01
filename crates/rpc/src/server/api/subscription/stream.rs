use std::future::Future;
use std::time::Duration;

use miden_node_store::DatabaseError;
use miden_node_utils::ErrorReport;
use miden_protocol::block::BlockNumber;
use tokio::sync::mpsc::error::SendTimeoutError;
use tokio::sync::watch;
use tokio_stream::Stream;
use tokio_stream::wrappers::ReceiverStream;

/// Buffered messages per subscriber before back-pressure begins.
const SUBSCRIBER_CHANNEL_CAPACITY: usize = 32;
/// Safety-net timeout for a single send when the client has stalled.
const SEND_TIMEOUT: Duration = Duration::from_secs(10);
/// Maximum gap between tip and subscriber's requested starting block where the starting block is
/// greater than the tip.
const MAX_FUTURE_GAP_IN_SUBSCRIPTIONS: u32 = 100u32;

pub trait Subscription: Sized + Send {
    fn on_eos(&self, err: StreamError);

    fn get_data(
        &self,
        block: BlockNumber,
    ) -> impl Future<Output = Result<Vec<u8>, DataError>> + Send + '_;

    async fn into_stream(
        self,
        from: BlockNumber,
        mut chain_tip: watch::Receiver<BlockNumber>,
    ) -> tonic::Result<impl Stream<Item = Result<StreamEvent, StreamError>> + Send + 'static>
    where
        Self: 'static,
    {
        let tip = *chain_tip.borrow();
        if from.as_u32() > tip.as_u32().saturating_add(MAX_FUTURE_GAP_IN_SUBSCRIPTIONS) {
            return Err(tonic::Status::out_of_range(
                "subscription starting block is too far ahead of chain tip",
            ));
        }

        let (tx, rx) = tokio::sync::mpsc::channel(SUBSCRIBER_CHANNEL_CAPACITY);

        tokio::spawn(async move {
            let mut next = from;
            let mut lag_tracker = SubscriberLagTracker::default();

            let err = loop {
                // Wait for the requisite data to become part of the chain.
                let tip = tokio::select! {
                    biased;

                    () = tx.closed() => break StreamError::ConnectionClosed,
                    result = chain_tip.wait_for(|tip| tip >= &next) => match result {
                        Ok(tip) => *tip,
                        Err(_) => break StreamError::ServerShutdown,
                    },
                };

                // Ensure the client is keeping up with the chain.
                if lag_tracker.check(next, tip).is_err() {
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

                // Send the event but also check server shutdown condition so we don't hang for the
                // full timeout if the server is shutting down.
                let send_result = tokio::select! {
                    () = wait_for_server_shutdown(&mut chain_tip) => break StreamError::ServerShutdown,
                    result = tx.send_timeout(Ok(event), SEND_TIMEOUT) => result,
                };
                if let Err(err) = send_result.map_err(|err| match err {
                    SendTimeoutError::Timeout(_) => StreamError::SlowSubscriber,
                    SendTimeoutError::Closed(_) => StreamError::ConnectionClosed,
                }) {
                    break err;
                }

                next = next.child();
            };

            self.on_eos(err);
            let _ = tx.try_send(Err(err));
        });

        Ok(ReceiverStream::new(rx))
    }
}

async fn wait_for_server_shutdown(chain_tip: &mut watch::Receiver<BlockNumber>) {
    while chain_tip.changed().await.is_ok() {}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
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

struct SubscriberLagTracker {
    previous_gap: u32,
    running_total: u32,
}

impl Default for SubscriberLagTracker {
    fn default() -> Self {
        Self { previous_gap: u32::MAX, running_total: 0 }
    }
}

impl SubscriberLagTracker {
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

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use tokio_stream::StreamExt;

    use super::*;

    #[derive(Default)]
    struct MockStream {
        eos: Arc<Mutex<Vec<StreamError>>>,
        fetch_count: Arc<AtomicUsize>,
        fail_at: Option<BlockNumber>,
    }

    impl MockStream {
        fn failing_at(block: BlockNumber) -> Self {
            Self { fail_at: Some(block), ..Self::default() }
        }

        fn eos(&self) -> Arc<Mutex<Vec<StreamError>>> {
            Arc::clone(&self.eos)
        }

        fn fetch_count(&self) -> Arc<AtomicUsize> {
            Arc::clone(&self.fetch_count)
        }
    }

    impl Subscription for MockStream {
        fn on_eos(&self, err: StreamError) {
            self.eos.lock().expect("eos mutex should not be poisoned").push(err);
        }

        async fn get_data(&self, block: BlockNumber) -> Result<Vec<u8>, DataError> {
            self.fetch_count.fetch_add(1, Ordering::Relaxed);
            if Some(block) == self.fail_at {
                return Err(DataError::NotFound);
            }
            Ok(block.as_u32().to_be_bytes().to_vec())
        }
    }

    #[tokio::test]
    async fn stream_waiting_for_tip_returns_server_shutdown_when_tip_sender_closes() {
        let (tip_tx, tip_rx) = watch::channel(BlockNumber::GENESIS);
        let source = MockStream::default();
        let eos = source.eos();
        let mut stream = source
            .into_stream(BlockNumber::from(1u32), tip_rx)
            .await
            .expect("subscription start should be valid");

        drop(tip_tx);

        let item = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("stream must yield promptly")
            .expect("stream must not end without an item");
        assert!(matches!(item, Err(StreamError::ServerShutdown)));

        assert!(matches!(
            eos.lock().expect("eos mutex should not be poisoned").as_slice(),
            [StreamError::ServerShutdown],
        ));
    }

    #[tokio::test]
    async fn stream_yields_requested_block_once_tip_reaches_it() {
        let (_tip_tx, tip_rx) = watch::channel(BlockNumber::from(1u32));
        let mut stream = MockStream::default()
            .into_stream(BlockNumber::from(1u32), tip_rx)
            .await
            .expect("subscription start should be valid");

        let item = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("stream must yield promptly")
            .expect("stream must not end without an item")
            .expect("stream event must be ok");

        assert_eq!(item.block, BlockNumber::from(1u32));
        assert_eq!(item.tip, BlockNumber::from(1u32));
        assert_eq!(item.data, 1u32.to_be_bytes().to_vec());
    }

    #[tokio::test]
    async fn data_error_returns_internal_and_reports_eos() {
        let (_tip_tx, tip_rx) = watch::channel(BlockNumber::from(1u32));
        let source = MockStream::failing_at(BlockNumber::from(1u32));
        let eos = source.eos();
        let mut stream = source
            .into_stream(BlockNumber::from(1u32), tip_rx)
            .await
            .expect("subscription start should be valid");

        let item = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("stream must yield promptly")
            .expect("stream must not end without an item");
        assert!(matches!(item, Err(StreamError::Internal)));

        assert!(matches!(
            eos.lock().expect("eos mutex should not be poisoned").as_slice(),
            [StreamError::Internal],
        ));
    }

    #[tokio::test]
    async fn stream_waiting_for_tip_exits_when_receiver_is_dropped() {
        let (_tip_tx, tip_rx) = watch::channel(BlockNumber::GENESIS);
        let source = MockStream::default();
        let eos = source.eos();
        let stream = source
            .into_stream(BlockNumber::from(1u32), tip_rx)
            .await
            .expect("subscription start should be valid");

        drop(stream);

        wait_for_eos(&eos, StreamError::ConnectionClosed).await;
    }

    #[tokio::test]
    async fn shutdown_while_send_is_pending_reports_server_shutdown() {
        let (tip_tx, tip_rx) =
            watch::channel(BlockNumber::from((SUBSCRIBER_CHANNEL_CAPACITY + 1) as u32));
        let source = MockStream::default();
        let eos = source.eos();
        let fetch_count = source.fetch_count();
        let _stream = source
            .into_stream(BlockNumber::GENESIS, tip_rx)
            .await
            .expect("subscription start should be valid");

        wait_for_fetch_count(&fetch_count, SUBSCRIBER_CHANNEL_CAPACITY + 1).await;
        drop(tip_tx);

        wait_for_eos(&eos, StreamError::ServerShutdown).await;
    }

    #[tokio::test]
    async fn subscription_start_may_be_at_or_behind_chain_tip() {
        assert_subscription_start_ok(0, 10).await;
        assert_subscription_start_ok(10, 10).await;
    }

    #[tokio::test]
    async fn subscription_start_may_be_within_future_gap() {
        assert_subscription_start_ok(10 + MAX_FUTURE_GAP_IN_SUBSCRIPTIONS, 10).await;

        let err = subscription_start_err(10 + MAX_FUTURE_GAP_IN_SUBSCRIPTIONS + 1, 10).await;
        assert_eq!(err.code(), tonic::Code::OutOfRange);
    }

    #[tokio::test]
    async fn subscription_start_future_gap_check_saturates_at_max_block() {
        assert_subscription_start_ok(u32::MAX, u32::MAX - 10).await;
    }

    async fn wait_for_eos(eos: &Arc<Mutex<Vec<StreamError>>>, expected: StreamError) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if eos.lock().expect("eos mutex should not be poisoned").as_slice() == [expected] {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("stream must report eos promptly");
    }

    async fn wait_for_fetch_count(fetch_count: &AtomicUsize, expected: usize) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while fetch_count.load(Ordering::Relaxed) < expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("stream must fetch events promptly");
    }

    async fn assert_subscription_start_ok(block_from: u32, chain_tip: u32) {
        let (tip_tx, tip_rx) = watch::channel(BlockNumber::from(chain_tip));
        let stream = MockStream::default().into_stream(BlockNumber::from(block_from), tip_rx).await;

        assert!(stream.is_ok());
        drop(stream);
        drop(tip_tx);
    }

    async fn subscription_start_err(block_from: u32, chain_tip: u32) -> tonic::Status {
        let (_tip_tx, tip_rx) = watch::channel(BlockNumber::from(chain_tip));

        match MockStream::default().into_stream(BlockNumber::from(block_from), tip_rx).await {
            Ok(_) => panic!("subscription start should be rejected"),
            Err(err) => err,
        }
    }

    fn run(gaps: &[u32]) -> Result<(), ()> {
        let mut lag_tracker = SubscriberLagTracker::default();
        for &gap in gaps {
            lag_tracker.check(BlockNumber::GENESIS, BlockNumber::from(gap))?;
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
        assert!(run(&[10, 20, SubscriberLagTracker::MAX_RUNNING_GAP - 1, 5]).is_ok());
    }

    #[test]
    fn starting_above_max_growth_is_ok() {
        assert!(run(&[SubscriberLagTracker::MAX_RUNNING_GAP * 2]).is_ok());
    }

    #[test]
    fn exactly_max_growth_run_is_ok() {
        // A single jump of exactly MAX_RUNNING_GAP is the boundary — still ok.
        assert!(run(&[0, SubscriberLagTracker::MAX_RUNNING_GAP]).is_ok());
    }

    #[test]
    fn exceeding_max_growth_run_returns_too_slow() {
        // One block past the limit triggers TooSlow, even in a single jump.
        assert!(matches!(run(&[0, SubscriberLagTracker::MAX_RUNNING_GAP + 1]), Err(())));
    }

    #[test]
    fn growth_spread_across_windows_accumulates() {
        // Many small growths that each stay below the limit still trigger TooSlow once they sum
        // past MAX_RUNNING_GAP.
        let step = SubscriberLagTracker::MAX_RUNNING_GAP / 4;
        let gaps: Vec<u32> = (1..=6).map(|i| i * step).collect(); // total growth = 5 * step
        assert!(matches!(run(&gaps), Err(())));
    }

    #[test]
    fn recovery_reduces_and_allows_fresh_accumulation() {
        // Grow close to the limit, recover most of the way, then grow again — still ok.
        let near_limit = SubscriberLagTracker::MAX_RUNNING_GAP - 1;
        assert!(run(&[near_limit, 1, near_limit]).is_ok());
    }

    #[test]
    fn token_improvement_does_not_prevent_disconnection() {
        // A client that grows by a large amount then shrinks by just one block on each cycle
        // accumulates net growth and is eventually disconnected.
        let gaps: Vec<u32> = (0u32..SubscriberLagTracker::MAX_RUNNING_GAP + 10)
            .flat_map(|i| [50 + i, 49 + i])
            .collect();
        assert!(matches!(run(&gaps), Err(())));
    }
}
