use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use miden_node_proto::generated as grpc;
use miden_node_store::BlockStore;
use miden_node_utils::ErrorReport;
use miden_node_utils::tracing::OpenTelemetrySpanExt;
use miden_protocol::block::BlockNumber;
use tokio::sync::{mpsc, watch};
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::{Stream, StreamExt};
use tonic::Status;
use tracing::Span;

use super::ValidatorService;

/// Buffered blocks per subscriber before back-pressure begins.
const SUBSCRIBER_CHANNEL_CAPACITY: usize = 32;
/// Safety-net timeout for a single send when the client has stalled. A subscriber that fails to
/// drain a buffered block within this window is disconnected so it cannot pin validator resources.
const SEND_TIMEOUT: Duration = Duration::from_secs(10);

type BlockSubscriptionStream = Pin<
    Box<
        dyn Stream<Item = tonic::Result<grpc::validator::BlockSubscriptionResponse>>
            + Send
            + 'static,
    >,
>;

#[tonic::async_trait]
impl grpc::server::validator_api::BlockSubscription for ValidatorService {
    type Input = grpc::validator::BlockSubscriptionRequest;
    type Item = grpc::validator::BlockSubscriptionResponse;
    type ItemStream = BlockSubscriptionStream;

    fn decode(request: grpc::validator::BlockSubscriptionRequest) -> tonic::Result<Self::Input> {
        Ok(request)
    }

    fn encode(item: Self::Item) -> tonic::Result<grpc::validator::BlockSubscriptionResponse> {
        Ok(item)
    }

    async fn handle(&self, request: Self::Input) -> tonic::Result<Self::ItemStream> {
        Span::current().set_attribute("block.from", request.block_from);

        // Cap concurrent subscriptions. The permit is moved into the streaming task and released
        // once the stream ends or the client disconnects.
        let permit = Arc::clone(&self.block_subscription_semaphore)
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("maximum block subscriptions reached"))?;

        let from = BlockNumber::from(request.block_from);
        let stream = build_block_stream(
            from,
            self.committed_tip.subscribe(),
            self.block_store.clone(),
            permit,
        )
        .map(|event| event.map_err(subscription_error_to_status));

        Ok(Box::pin(stream))
    }
}

// STREAM
// ================================================================================================

#[derive(Debug, thiserror::Error)]
enum BlockSubscriptionError {
    #[error("failed to load block {block_num}")]
    BlockLoad {
        block_num: BlockNumber,
        #[source]
        source: std::io::Error,
    },
    #[error("block {0} not found")]
    BlockNotFound(BlockNumber),
    #[error("subscriber is too slow to keep up with the chain")]
    TooSlow,
}

/// Spawns a task that replays backed-up blocks from `from` and then follows live signed blocks,
/// emitting each as a [`grpc::validator::BlockSubscriptionResponse`] on the returned stream.
fn build_block_stream(
    from: BlockNumber,
    tip_rx: watch::Receiver<BlockNumber>,
    block_store: BlockStore,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> impl Stream<Item = Result<grpc::validator::BlockSubscriptionResponse, BlockSubscriptionError>>
+ Send
+ 'static {
    let (tx, rx) = mpsc::channel(SUBSCRIBER_CHANNEL_CAPACITY);
    tokio::spawn(async move {
        // Hold the subscription permit for the lifetime of the streaming task.
        let _permit = permit;
        if let Err(err) = run_block_stream(from, tip_rx, &tx, &block_store).await {
            let _ = tx.send(Err(err)).await;
        }
    });
    ReceiverStream::new(rx)
}

/// Drives a block subscription, replaying history then following live tip advances.
///
/// Loads each block in sequence starting from `from` and sends it to `tx`. Disconnects the
/// subscriber with [`BlockSubscriptionError::TooSlow`] if a single send blocks for longer than
/// [`SEND_TIMEOUT`], which can only happen once [`SUBSCRIBER_CHANNEL_CAPACITY`] blocks are queued.
async fn run_block_stream(
    from: BlockNumber,
    mut tip_rx: watch::Receiver<BlockNumber>,
    tx: &mpsc::Sender<Result<grpc::validator::BlockSubscriptionResponse, BlockSubscriptionError>>,
    block_store: &BlockStore,
) -> Result<(), BlockSubscriptionError> {
    let mut next = from;
    loop {
        let mut tip = *tip_rx.borrow_and_update();

        while next <= tip {
            let block = block_store
                .load_block(next)
                .await
                .map_err(|source| BlockSubscriptionError::BlockLoad { block_num: next, source })?
                .ok_or(BlockSubscriptionError::BlockNotFound(next))?;
            // Re-read the tip so the emitted value reflects any blocks signed during the load.
            tip = *tip_rx.borrow_and_update();
            let permit = match tokio::time::timeout(SEND_TIMEOUT, tx.reserve()).await {
                Ok(Ok(permit)) => permit,
                // The subscriber disconnected; end the stream cleanly.
                Ok(Err(_)) => return Ok(()),
                Err(_) => return Err(BlockSubscriptionError::TooSlow),
            };
            permit.send(Ok(grpc::validator::BlockSubscriptionResponse {
                block,
                committed_chain_tip: tip.as_u32(),
            }));
            next = next.child();
        }

        // Wait for the next signed block. An error means all senders dropped, i.e. shutdown.
        if tip_rx.changed().await.is_err() {
            return Ok(());
        }
    }
}

fn subscription_error_to_status(err: BlockSubscriptionError) -> Status {
    match err {
        BlockSubscriptionError::BlockNotFound(block_num) => {
            Status::not_found(format!("block {block_num} not found"))
        },
        BlockSubscriptionError::BlockLoad { block_num, source } => {
            Status::internal(format!("failed to load block {block_num}: {}", source.as_report()))
        },
        BlockSubscriptionError::TooSlow => {
            Status::resource_exhausted("subscriber is too slow to keep up with the chain")
        },
    }
}
