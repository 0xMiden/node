use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use miden_protocol::block::BlockNumber;
use tokio::sync::{Semaphore, watch};
use tokio_stream::StreamExt;

use super::*;

struct TestSubscription {
    ban_list: Arc<IpBanList>,
    semaphore: Arc<Semaphore>,
    fetch_count: Arc<AtomicUsize>,
    fail_at: Option<BlockNumber>,
}

impl Default for TestSubscription {
    fn default() -> Self {
        Self {
            ban_list: Arc::new(IpBanList::default()),
            semaphore: Arc::new(Semaphore::new(1)),
            fetch_count: Arc::new(AtomicUsize::new(0)),
            fail_at: None,
        }
    }
}

impl TestSubscription {
    fn failing_at(block: BlockNumber) -> Self {
        Self { fail_at: Some(block), ..Self::default() }
    }

    fn fetch_count(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.fetch_count)
    }

    fn stream(
        &self,
        from: BlockNumber,
        chain_tip: watch::Receiver<BlockNumber>,
    ) -> tonic::Result<SubscriptionStream> {
        self.stream_for_ip(None, from, chain_tip)
    }

    fn stream_for_ip(
        &self,
        client_ip: Option<IpAddr>,
        from: BlockNumber,
        chain_tip: watch::Receiver<BlockNumber>,
    ) -> tonic::Result<SubscriptionStream> {
        let fetch_count = Arc::clone(&self.fetch_count);
        let fail_at = self.fail_at;

        SubscriptionStream::create(
            from,
            client_ip,
            Arc::clone(&self.ban_list),
            Arc::clone(&self.semaphore),
            chain_tip,
            move |block| {
                fetch_count.fetch_add(1, Ordering::Relaxed);
                let result = if Some(block) == fail_at {
                    Err(DataError::NotFound)
                } else {
                    Ok(block.as_u32().to_be_bytes().to_vec())
                };
                std::future::ready(result)
            },
        )
    }
}

#[tokio::test]
async fn stream_waiting_for_tip_returns_server_shutdown_when_tip_sender_closes() {
    let (tip_tx, tip_rx) = watch::channel(BlockNumber::GENESIS);
    let source = TestSubscription::default();
    let mut stream = source
        .stream(BlockNumber::from(1u32), tip_rx)
        .expect("subscription start should be valid");

    drop(tip_tx);

    let item = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("stream must yield promptly")
        .expect("stream must not end without an item");
    assert_stream_status(item, tonic::Code::Unavailable);

    wait_for_subscription_exit(&source).await;
}

#[tokio::test]
async fn stream_yields_requested_block_once_tip_reaches_it() {
    let (_tip_tx, tip_rx) = watch::channel(BlockNumber::from(1u32));
    let mut stream = TestSubscription::default()
        .stream(BlockNumber::from(1u32), tip_rx)
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
    let source = TestSubscription::failing_at(BlockNumber::from(1u32));
    let mut stream = source
        .stream(BlockNumber::from(1u32), tip_rx)
        .expect("subscription start should be valid");

    let item = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("stream must yield promptly")
        .expect("stream must not end without an item");
    assert_stream_status(item, tonic::Code::Internal);

    wait_for_subscription_exit(&source).await;
}

#[tokio::test]
async fn stream_waiting_for_tip_exits_when_receiver_is_dropped() {
    let (_tip_tx, tip_rx) = watch::channel(BlockNumber::GENESIS);
    let source = TestSubscription::default();
    let stream = source
        .stream(BlockNumber::from(1u32), tip_rx)
        .expect("subscription start should be valid");

    drop(stream);

    wait_for_subscription_exit(&source).await;
}

#[tokio::test]
async fn shutdown_while_send_is_pending_reports_server_shutdown() {
    let (tip_tx, tip_rx) =
        watch::channel(BlockNumber::from((SUBSCRIBER_CHANNEL_CAPACITY + 1) as u32));
    let source = TestSubscription::default();
    let fetch_count = source.fetch_count();
    let _stream = source
        .stream(BlockNumber::GENESIS, tip_rx)
        .expect("subscription start should be valid");

    wait_for_fetch_count(&fetch_count, SUBSCRIBER_CHANNEL_CAPACITY + 1).await;
    drop(tip_tx);

    wait_for_subscription_exit(&source).await;
}

#[tokio::test]
async fn slow_subscriber_is_banned() {
    let (tip_tx, tip_rx) = watch::channel(BlockNumber::GENESIS);
    let source = TestSubscription::default();
    let client_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let mut stream = source
        .stream_for_ip(Some(client_ip), BlockNumber::GENESIS, tip_rx)
        .expect("subscription start should be valid");

    let first_item = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("stream must yield promptly")
        .expect("stream must not end without an item")
        .expect("stream event must be ok");
    assert_eq!(first_item.block, BlockNumber::GENESIS);

    tip_tx
        .send(BlockNumber::from(SubscriberLagTracker::MAX_RUNNING_GAP + 2))
        .expect("chain tip receiver should be open");

    let item = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("stream must yield promptly")
        .expect("stream must not end without an item");
    assert_stream_status(item, tonic::Code::ResourceExhausted);
    assert!(source.ban_list.banned_until(client_ip).is_some());
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

async fn wait_for_subscription_exit(source: &TestSubscription) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while source.semaphore.available_permits() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("stream task must release subscription permit promptly");
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

fn assert_stream_status(item: tonic::Result<StreamItem>, code: tonic::Code) {
    let Err(err) = item else {
        panic!("stream item must be an error");
    };

    assert_eq!(err.code(), code);
}

async fn assert_subscription_start_ok(block_from: u32, chain_tip: u32) {
    let (tip_tx, tip_rx) = watch::channel(BlockNumber::from(chain_tip));
    let source = TestSubscription::default();
    let stream = source.stream(BlockNumber::from(block_from), tip_rx);

    assert!(stream.is_ok());
    drop(stream);
    drop(tip_tx);
    wait_for_subscription_exit(&source).await;
}

async fn subscription_start_err(block_from: u32, chain_tip: u32) -> tonic::Status {
    let (_tip_tx, tip_rx) = watch::channel(BlockNumber::from(chain_tip));
    let source = TestSubscription::default();

    match source.stream(BlockNumber::from(block_from), tip_rx) {
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
    // Gap stays constant; delta is always 0, growth_run never increments.
    assert!(run(&[5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5]).is_ok());
}

#[test]
fn zero_gap_throughout_is_ok() {
    assert!(run(&[0, 0, 0, 0, 0]).is_ok());
}

#[test]
fn shrinking_gap_reduces_accumulation() {
    // Accumulate close to the limit, then shrink; running total decreases, no error.
    assert!(run(&[10, 20, SubscriberLagTracker::MAX_RUNNING_GAP - 1, 5]).is_ok());
}

#[test]
fn starting_above_max_growth_is_ok() {
    assert!(run(&[SubscriberLagTracker::MAX_RUNNING_GAP * 2]).is_ok());
}

#[test]
fn exactly_max_growth_run_is_ok() {
    // A single jump of exactly MAX_RUNNING_GAP is the boundary; still ok.
    assert!(run(&[0, SubscriberLagTracker::MAX_RUNNING_GAP]).is_ok());
}

#[test]
fn exceeding_max_growth_run_returns_too_slow() {
    // One block past the limit triggers TooSlow, even in a single jump.
    assert!(matches!(run(&[0, SubscriberLagTracker::MAX_RUNNING_GAP + 1]), Err(())));
}

#[test]
fn growth_spread_across_windows_accumulates() {
    // Many small growths that each stay below the limit still trigger TooSlow once they sum past
    // MAX_RUNNING_GAP.
    let step = SubscriberLagTracker::MAX_RUNNING_GAP / 4;
    let gaps: Vec<u32> = (1..=6).map(|i| i * step).collect();
    assert!(matches!(run(&gaps), Err(())));
}

#[test]
fn recovery_reduces_and_allows_fresh_accumulation() {
    // Grow close to the limit, recover most of the way, then grow again; still ok.
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
