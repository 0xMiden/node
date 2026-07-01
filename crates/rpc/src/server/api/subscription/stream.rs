use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use miden_node_store::DatabaseError;
use miden_node_utils::ErrorReport;
use miden_protocol::block::BlockNumber;
use tokio::sync::mpsc::error::SendTimeoutError;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch};
use tokio_stream::wrappers::ReceiverStream;

use super::super::RpcService;
use super::{IpBanList, subscription_ban_status};

/// Buffered messages per subscriber before back-pressure begins.
const SUBSCRIBER_CHANNEL_CAPACITY: usize = 32;
/// Safety-net timeout for a single send when the client has stalled.
const SEND_TIMEOUT: Duration = Duration::from_secs(10);
/// Maximum gap between tip and subscriber's requested starting block where the starting block is
/// greater than the tip.
const MAX_FUTURE_GAP_IN_SUBSCRIPTIONS: u32 = 100u32;

impl SubscriptionStream {
    pub(super) fn blocks(
        rpc: &RpcService,
        from: BlockNumber,
        client_ip: Option<IpAddr>,
    ) -> tonic::Result<SubscriptionStream> {
        let store = Arc::clone(&rpc.store);

        Self::create(
            from,
            client_ip,
            Arc::clone(&rpc.subscription_ban),
            Arc::clone(&rpc.block_subscription_semaphore),
            rpc.store.subscribe_committed_tip(),
            move |block| {
                let store = Arc::clone(&store);
                async move {
                    store
                        .load_block(block)
                        .await
                        .map_err(|source| DataError::DatabaseError { source })?
                        .ok_or(DataError::NotFound)
                }
            },
        )
    }

    pub(super) fn proofs(
        rpc: &RpcService,
        from: BlockNumber,
        client_ip: Option<IpAddr>,
    ) -> tonic::Result<SubscriptionStream> {
        let store = Arc::clone(&rpc.store);

        Self::create(
            from,
            client_ip,
            Arc::clone(&rpc.subscription_ban),
            Arc::clone(&rpc.proof_subscription_semaphore),
            rpc.store.subscribe_proven_tip(),
            move |block| {
                let store = Arc::clone(&store);
                async move {
                    store
                        .load_proof(block)
                        .await
                        .map_err(|source| DataError::DatabaseError { source })?
                        .ok_or(DataError::NotFound)
                }
            },
        )
    }

    fn new(inner: ReceiverStream<tonic::Result<StreamItem>>) -> Self {
        Self { inner }
    }

    fn create<GetData, Fut>(
        from: BlockNumber,
        client_ip: Option<IpAddr>,
        ban_list: Arc<IpBanList>,
        subscription_semaphore: Arc<Semaphore>,
        chain_tip: watch::Receiver<BlockNumber>,
        get_data: GetData,
    ) -> tonic::Result<SubscriptionStream>
    where
        GetData: Fn(BlockNumber) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Vec<u8>, DataError>> + Send + 'static,
    {
        validate_start(from, &chain_tip)?;

        let context = SubscriptionContext::new(client_ip, ban_list, subscription_semaphore)?;
        let (tx, rx) = mpsc::channel(SUBSCRIBER_CHANNEL_CAPACITY);
        SubscriptionProducer::new(from, chain_tip, tx, context, get_data).spawn();

        Ok(SubscriptionStream::new(ReceiverStream::new(rx)))
    }
}

fn validate_start(
    from: BlockNumber,
    chain_tip: &watch::Receiver<BlockNumber>,
) -> tonic::Result<()> {
    let tip = *chain_tip.borrow();
    if from.as_u32() > tip.as_u32().saturating_add(MAX_FUTURE_GAP_IN_SUBSCRIPTIONS) {
        return Err(tonic::Status::out_of_range(
            "subscription starting block is too far ahead of chain tip",
        ));
    }

    Ok(())
}

struct SubscriptionProducer<GetData> {
    next: BlockNumber,
    chain_tip: watch::Receiver<BlockNumber>,
    tx: mpsc::Sender<tonic::Result<StreamItem>>,
    context: SubscriptionContext,
    get_data: GetData,
    lag_tracker: SubscriberLagTracker,
}

impl<GetData, Fut> SubscriptionProducer<GetData>
where
    GetData: Fn(BlockNumber) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Vec<u8>, DataError>> + Send + 'static,
{
    fn new(
        from: BlockNumber,
        chain_tip: watch::Receiver<BlockNumber>,
        tx: mpsc::Sender<tonic::Result<StreamItem>>,
        context: SubscriptionContext,
        get_data: GetData,
    ) -> Self {
        Self {
            next: from,
            chain_tip,
            tx,
            context,
            get_data,
            lag_tracker: SubscriberLagTracker::default(),
        }
    }

    fn spawn(self) {
        tokio::spawn(self.run());
    }

    async fn run(mut self) {
        let err = match self.produce_until_error().await {
            Ok(()) => unreachable!("subscription producer loop does not exit successfully"),
            Err(err) => err,
        };

        self.context.on_eos(err);
        let _ = self.tx.try_send(Err(err.into_status()));
    }

    async fn produce_until_error(&mut self) -> Result<(), StreamError> {
        loop {
            self.produce_next().await?;
        }
    }

    async fn produce_next(&mut self) -> Result<(), StreamError> {
        let tip = self.wait_for_tip().await?;
        self.lag_tracker
            .check(self.next, tip)
            .map_err(|()| StreamError::SlowSubscriber)?;

        let data = self.load_data().await?;
        let event = StreamItem { data, block: self.next, tip };
        self.send_event(event).await?;

        self.next = self.next.child();
        Ok(())
    }

    async fn wait_for_tip(&mut self) -> Result<BlockNumber, StreamError> {
        let next = self.next;

        tokio::select! {
            biased;

            () = self.tx.closed() => Err(StreamError::ConnectionClosed),
            result = self.chain_tip.wait_for(|tip| tip >= &next) => {
                result.map(|tip| *tip).map_err(|_| StreamError::ServerShutdown)
            },
        }
    }

    async fn load_data(&self) -> Result<Vec<u8>, StreamError> {
        let block = self.next;
        (self.get_data)(block)
            .await
            .inspect_err(|err| {
                tracing::error!(
                    block.number = %block,
                    message = %err.as_report(),
                    "failed to load data for stream"
                );
            })
            .map_err(|_| StreamError::Internal)
    }

    async fn send_event(&mut self, event: StreamItem) -> Result<(), StreamError> {
        let send_result = tokio::select! {
            () = wait_for_server_shutdown(&mut self.chain_tip) => {
                return Err(StreamError::ServerShutdown);
            },
            result = self.tx.send_timeout(Ok(event), SEND_TIMEOUT) => result,
        };

        send_result.map_err(|err| match err {
            SendTimeoutError::Timeout(_) => StreamError::SlowSubscriber,
            SendTimeoutError::Closed(_) => StreamError::ConnectionClosed,
        })
    }
}

pub struct SubscriptionStream {
    inner: ReceiverStream<tonic::Result<StreamItem>>,
}

impl tokio_stream::Stream for SubscriptionStream {
    type Item = tonic::Result<StreamItem>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.get_mut().inner).poll_next(cx)
    }
}

struct SubscriptionContext {
    client_ip: Option<IpAddr>,
    ban_list: Arc<IpBanList>,
    _permit: OwnedSemaphorePermit,
}

impl SubscriptionContext {
    fn new(
        client_ip: Option<IpAddr>,
        ban_list: Arc<IpBanList>,
        subscription_semaphore: Arc<Semaphore>,
    ) -> tonic::Result<Self> {
        if let Some(until) = client_ip.and_then(|ip| ban_list.banned_until(ip)) {
            return Err(subscription_ban_status(until));
        }

        let permit = subscription_semaphore
            .try_acquire_owned()
            .map_err(|_| tonic::Status::resource_exhausted("maximum subscriptions reached"))?;

        Ok(Self { client_ip, ban_list, _permit: permit })
    }

    fn on_eos(&self, err: StreamError) {
        if let (Some(ip), StreamError::SlowSubscriber) = (self.client_ip, err) {
            self.ban_list.add(ip);
        }
    }
}

async fn wait_for_server_shutdown(chain_tip: &mut watch::Receiver<BlockNumber>) {
    while chain_tip.changed().await.is_ok() {}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StreamError {
    ServerShutdown,
    ConnectionClosed,
    SlowSubscriber,
    Internal,
}

impl StreamError {
    fn into_status(self) -> tonic::Status {
        match self {
            StreamError::ServerShutdown => tonic::Status::unavailable("server is shutting down"),
            StreamError::ConnectionClosed => tonic::Status::aborted("client closed the stream"),
            StreamError::SlowSubscriber => {
                tonic::Status::resource_exhausted("client is too slow to keep up with the chain")
            },
            StreamError::Internal => tonic::Status::internal("internal error"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum DataError {
    #[error("data not found")]
    NotFound,
    #[error(transparent)]
    DatabaseError { source: DatabaseError },
}

pub struct StreamItem {
    pub data: Vec<u8>,
    pub block: BlockNumber,
    pub tip: BlockNumber,
}

// LAG TRACKER
// ================================================================================================

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
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

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
