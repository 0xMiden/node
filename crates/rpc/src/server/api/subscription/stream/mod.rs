use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use miden_node_store::DatabaseError;
use miden_node_utils::ErrorReport;
use miden_protocol::block::BlockNumber;
use tokio::sync::mpsc::error::SendTimeoutError;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch};
use tokio_stream::wrappers::ReceiverStream;
use tonic::Status;

use super::super::RpcService;
use super::IpBanList;

#[cfg(test)]
mod tests;

/// Buffered messages per subscriber before back-pressure begins.
const SUBSCRIBER_CHANNEL_CAPACITY: usize = 32;
/// Safety-net timeout for a single send when the client has stalled.
const SEND_TIMEOUT: Duration = Duration::from_secs(10);
/// Maximum gap between tip and subscriber's requested starting block where the starting block is
/// greater than the tip.
const MAX_FUTURE_GAP_IN_SUBSCRIPTIONS: u32 = 100u32;

// STREAM
// ================================================================================================

/// A stream of either block or block proofs.
pub struct SubscriptionStream {
    inner: ReceiverStream<tonic::Result<StreamItem>>,
}

impl tokio_stream::Stream for SubscriptionStream {
    type Item = tonic::Result<StreamItem>;

    /// Polls the underlying receiver for the next subscription event or terminal status.
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.get_mut().inner).poll_next(cx)
    }
}

/// Raw subscription payload plus the chain position that produced it.
pub struct StreamItem {
    /// Encoded block or proof bytes.
    pub data: Vec<u8>,
    /// Block number for `data`.
    pub block: BlockNumber,
    /// Chain tip observed when `data` was sent.
    pub tip: BlockNumber,
}

impl SubscriptionStream {
    /// Creates a stream of committed blocks starting at `from`.
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
                async move { store.load_block(block).await }
            },
        )
    }

    /// Creates a stream of proven block proofs starting at `from`.
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
                async move { store.load_proof(block).await }
            },
        )
    }

    /// Builds a subscription stream around a spawned producer task.
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
        Fut: Future<Output = Result<Option<Vec<u8>>, DatabaseError>> + Send + 'static,
    {
        Self::validate_start(from, &chain_tip)?;
        Self::reject_banned_client(client_ip, &ban_list)?;
        let subscription_permit = Self::acquire_subscription_permit(subscription_semaphore)?;

        let (tx, rx) = mpsc::channel(SUBSCRIBER_CHANNEL_CAPACITY);
        let producer = SubscriptionProducer {
            next: from,
            chain_tip,
            tx,
            client_ip,
            ban_list,
            _subscription_permit: subscription_permit,
            get_data,
            lag_tracker: SubscriberLagTracker::default(),
        };
        producer.spawn();

        Ok(Self { inner: ReceiverStream::new(rx) })
    }

    /// Rejects subscriptions whose starting block is too far ahead of the current chain tip.
    fn validate_start(
        from: BlockNumber,
        chain_tip: &watch::Receiver<BlockNumber>,
    ) -> tonic::Result<()> {
        let tip = *chain_tip.borrow();
        if from.as_u32() > tip.as_u32().saturating_add(MAX_FUTURE_GAP_IN_SUBSCRIPTIONS) {
            return Err(Status::out_of_range(
                "subscription starting block is too far ahead of chain tip",
            ));
        }

        Ok(())
    }

    /// Rejects clients that are still temporarily banned for a previous slow subscription.
    fn reject_banned_client(client_ip: Option<IpAddr>, ban_list: &IpBanList) -> tonic::Result<()> {
        if let Some(until) = client_ip.and_then(|ip| ban_list.banned_until(ip)) {
            let remaining = until.saturating_duration_since(Instant::now());
            return Err(Status::resource_exhausted(format!(
                "temporarily banned from subscribing for being too slow; retry in {} seconds",
                // Round up so the reported wait never undershoots the actual remaining ban.
                remaining.as_secs() + 1,
            )));
        }

        Ok(())
    }

    /// Acquires one subscription slot for the lifetime of the producer task.
    fn acquire_subscription_permit(
        subscription_semaphore: Arc<Semaphore>,
    ) -> tonic::Result<OwnedSemaphorePermit> {
        subscription_semaphore
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("maximum subscriptions reached"))
    }
}

// PRODUCER
// ================================================================================================

/// Background task state that produces subscription events for one client.
struct SubscriptionProducer<GetData> {
    next: BlockNumber,
    chain_tip: watch::Receiver<BlockNumber>,
    tx: mpsc::Sender<tonic::Result<StreamItem>>,
    client_ip: Option<IpAddr>,
    ban_list: Arc<IpBanList>,
    _subscription_permit: OwnedSemaphorePermit,
    get_data: GetData,
    lag_tracker: SubscriberLagTracker,
}

impl<GetData, Fut> SubscriptionProducer<GetData>
where
    GetData: Fn(BlockNumber) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Option<Vec<u8>>, DatabaseError>> + Send + 'static,
{
    /// Spawns the producer task that feeds the receiver side of the subscription stream.
    fn spawn(self) {
        tokio::spawn(self.run());
    }

    /// Runs the producer until it reaches a terminal stream error, then reports that status.
    async fn run(mut self) {
        let err = self.produce_until_error().await;

        if let (Some(ip), StreamError::SlowSubscriber) = (self.client_ip, err) {
            self.ban_list.add(ip);
        }
        let _ = self.tx.try_send(Err(err.into_status()));
    }

    /// Produces stream items until a terminal stream error occurs.
    async fn produce_until_error(&mut self) -> StreamError {
        loop {
            if let Err(err) = self.produce_next().await {
                return err;
            }
        }
    }

    /// Produces the next available stream item and advances the next block pointer.
    async fn produce_next(&mut self) -> Result<(), StreamError> {
        let tip = self.wait_for_next_block().await?;
        if !self.lag_tracker.record_and_check(self.next, tip) {
            return Err(StreamError::SlowSubscriber);
        }

        let data = self.load_data().await?;
        let event = StreamItem { data, block: self.next, tip };
        self.send_event(event).await?;

        self.next = self.next.child();
        Ok(())
    }

    /// Waits until `self.next` is included by the chain tip.
    async fn wait_for_next_block(&mut self) -> Result<BlockNumber, StreamError> {
        let next = self.next;

        tokio::select! {
            biased;

            () = self.tx.closed() => Err(StreamError::ConnectionClosed),
            result = self.chain_tip.wait_for(|tip| tip >= &next) => {
                result.map(|tip| *tip).map_err(|_| StreamError::ServerShutdown)
            },
        }
    }

    /// Loads the bytes for `self.next` from the stream-specific data source.
    async fn load_data(&self) -> Result<Vec<u8>, StreamError> {
        let block = self.next;
        let data = (self.get_data)(block)
            .await
            .inspect_err(|err| {
                tracing::error!(
                    block.number = %block,
                    message = %err.as_report(),
                    "failed to load data for stream"
                );
            })
            .map_err(|_| StreamError::Internal)?;

        data.ok_or_else(|| {
            tracing::error!(block.number = %block, "stream data not found");
            StreamError::Internal
        })
    }

    /// Sends a stream item to the client while also observing server shutdown.
    async fn send_event(&mut self, event: StreamItem) -> Result<(), StreamError> {
        let send_result = tokio::select! {
            () = Self::wait_for_server_shutdown(&mut self.chain_tip) => {
                return Err(StreamError::ServerShutdown);
            },
            result = self.tx.send_timeout(Ok(event), SEND_TIMEOUT) => result,
        };

        send_result.map_err(|err| match err {
            SendTimeoutError::Timeout(_) => StreamError::SlowSubscriber,
            SendTimeoutError::Closed(_) => StreamError::ConnectionClosed,
        })
    }

    /// Waits for the chain-tip watcher to close, which is this stream's shutdown signal.
    async fn wait_for_server_shutdown(chain_tip: &mut watch::Receiver<BlockNumber>) {
        while chain_tip.changed().await.is_ok() {}
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StreamError {
    ServerShutdown,
    ConnectionClosed,
    SlowSubscriber,
    Internal,
}

impl StreamError {
    /// Converts a terminal stream error into the gRPC status sent to the client.
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

// LAG TRACKER
// ================================================================================================

/// Tracks how far a subscriber falls behind the chain tip over time.
struct SubscriberLagTracker {
    previous_gap: u32,
    running_total: u32,
}

impl Default for SubscriberLagTracker {
    /// Creates a tracker with no accumulated lag.
    fn default() -> Self {
        Self { previous_gap: u32::MAX, running_total: 0 }
    }
}

impl SubscriberLagTracker {
    /// Maximum accumulated block-gap allowed before a subscriber is disconnected.
    const MAX_RUNNING_GAP: u32 = 100;

    /// Records the latest subscriber gap and returns whether it is still within the allowed limit.
    fn record_and_check(&mut self, current: BlockNumber, tip: BlockNumber) -> bool {
        let gap = tip.saturating_sub(current.as_u32()).as_u32();

        self.running_total = if gap > self.previous_gap {
            self.running_total + (gap - self.previous_gap)
        } else {
            self.running_total.saturating_sub(self.previous_gap - gap)
        };

        self.previous_gap = gap;

        self.running_total <= Self::MAX_RUNNING_GAP
    }
}
