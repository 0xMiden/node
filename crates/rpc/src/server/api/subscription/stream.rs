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

pub struct SubscriptionStream {
    inner: ReceiverStream<tonic::Result<StreamItem>>,
}

impl tokio_stream::Stream for SubscriptionStream {
    type Item = tonic::Result<StreamItem>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.get_mut().inner).poll_next(cx)
    }
}

pub struct StreamItem {
    pub data: Vec<u8>,
    pub block: BlockNumber,
    pub tip: BlockNumber,
}

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
                async move { store.load_block(block).await }
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
                async move { store.load_proof(block).await }
            },
        )
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
        Fut: Future<Output = Result<Option<Vec<u8>>, DatabaseError>> + Send + 'static,
    {
        let tip = *chain_tip.borrow();
        if from.as_u32() > tip.as_u32().saturating_add(MAX_FUTURE_GAP_IN_SUBSCRIPTIONS) {
            return Err(tonic::Status::out_of_range(
                "subscription starting block is too far ahead of chain tip",
            ));
        }

        if let Some(until) = client_ip.and_then(|ip| ban_list.banned_until(ip)) {
            let remaining = until.saturating_duration_since(Instant::now());
            return Err(Status::resource_exhausted(format!(
                "temporarily banned from subscribing for being too slow; retry in {} seconds",
                // Round up so the reported wait never undershoots the actual remaining ban.
                remaining.as_secs() + 1,
            )));
        }

        let permit = subscription_semaphore
            .try_acquire_owned()
            .map_err(|_| tonic::Status::resource_exhausted("maximum subscriptions reached"))?;

        let (tx, rx) = mpsc::channel(SUBSCRIBER_CHANNEL_CAPACITY);
        SubscriptionProducer {
            next: from,
            chain_tip,
            tx,
            client_ip,
            ban_list,
            _permit: permit,
            get_data,
            lag_tracker: SubscriberLagTracker::default(),
        }
        .spawn();

        Ok(Self { inner: ReceiverStream::new(rx) })
    }
}

// PRODUCER
// ================================================================================================

struct SubscriptionProducer<GetData> {
    next: BlockNumber,
    chain_tip: watch::Receiver<BlockNumber>,
    tx: mpsc::Sender<tonic::Result<StreamItem>>,
    client_ip: Option<IpAddr>,
    ban_list: Arc<IpBanList>,
    _permit: OwnedSemaphorePermit,
    get_data: GetData,
    lag_tracker: SubscriberLagTracker,
}

impl<GetData, Fut> SubscriptionProducer<GetData>
where
    GetData: Fn(BlockNumber) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Option<Vec<u8>>, DatabaseError>> + Send + 'static,
{
    fn spawn(self) {
        tokio::spawn(self.run());
    }

    async fn run(mut self) {
        let err = match self.produce_until_error().await {
            Ok(()) => unreachable!("subscription producer loop does not exit successfully"),
            Err(err) => err,
        };

        if let (Some(ip), StreamError::SlowSubscriber) = (self.client_ip, err) {
            self.ban_list.add(ip);
        }
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
