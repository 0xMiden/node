use std::pin::Pin;
use std::sync::Arc;

use miden_node_proto::generated as grpc;
use miden_node_store::BlockStore;
use miden_node_store::state::{
    SUBSCRIBER_CHANNEL_CAPACITY,
    StateSubscriptionError,
    SubscriptionSource,
    run_stream,
};
use miden_node_utils::ErrorReport;
use miden_node_utils::tracing::OpenTelemetrySpanExt;
use miden_protocol::block::BlockNumber;
use tokio::sync::{mpsc, watch};
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::{Stream, StreamExt};
use tonic::Status;
use tracing::Span;

use super::ValidatorService;

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

/// Streams committed blocks from the validator's [`BlockStore`], emitting each as a
/// [`grpc::validator::BlockSubscriptionResponse`].
struct BlockStoreSource {
    block_store: BlockStore,
}

impl SubscriptionSource for BlockStoreSource {
    type Event = grpc::validator::BlockSubscriptionResponse;

    async fn fetch(&self, block_num: BlockNumber) -> Result<Vec<u8>, StateSubscriptionError> {
        self.block_store
            .load_block(block_num)
            .await
            .map_err(|source| StateSubscriptionError::BlockLoad {
                block_num,
                source: source.into(),
            })?
            .ok_or(StateSubscriptionError::BlockNotFound(block_num))
    }

    fn build_event(
        &self,
        _block_num: BlockNumber,
        block: Vec<u8>,
        committed_chain_tip: BlockNumber,
    ) -> grpc::validator::BlockSubscriptionResponse {
        grpc::validator::BlockSubscriptionResponse {
            block,
            committed_chain_tip: committed_chain_tip.as_u32(),
        }
    }
}

/// Spawns a task that replays backed-up blocks from `from` and then follows live signed blocks,
/// emitting each as a [`grpc::validator::BlockSubscriptionResponse`] on the returned stream.
fn build_block_stream(
    from: BlockNumber,
    tip_rx: watch::Receiver<BlockNumber>,
    block_store: BlockStore,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> impl Stream<Item = Result<grpc::validator::BlockSubscriptionResponse, StateSubscriptionError>>
+ Send
+ 'static {
    let (tx, rx) = mpsc::channel(SUBSCRIBER_CHANNEL_CAPACITY);
    tokio::spawn(async move {
        // Hold the subscription permit for the lifetime of the streaming task.
        let _permit = permit;
        let source = BlockStoreSource { block_store };
        if let Err(err) = run_stream(from, tip_rx, &tx, source).await {
            let _ = tx.send(Err(err)).await;
        }
    });
    ReceiverStream::new(rx)
}

fn subscription_error_to_status(err: StateSubscriptionError) -> Status {
    match err {
        StateSubscriptionError::BlockNotFound(block_num)
        | StateSubscriptionError::ProofNotFound(block_num) => {
            Status::not_found(format!("block {block_num} not found"))
        },
        StateSubscriptionError::BlockLoad { block_num, source }
        | StateSubscriptionError::ProofLoad { block_num, source } => {
            Status::internal(format!("failed to load block {block_num}: {}", source.as_report()))
        },
        StateSubscriptionError::TooSlow => {
            Status::resource_exhausted("subscriber is too slow to keep up with the chain")
        },
    }
}
