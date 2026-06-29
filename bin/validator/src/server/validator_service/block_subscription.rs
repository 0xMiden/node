use std::pin::Pin;
use std::sync::Arc;

use miden_node_proto::generated as grpc;
use miden_node_store::BlockStore;
use miden_node_store::state::{SubscriptionSource, SubscriptionStreamError, run_stream};
use miden_node_utils::ErrorReport;
use miden_node_utils::tracing::OpenTelemetrySpanExt;
use miden_protocol::block::BlockNumber;
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

        // Hold the exclusive backup lock for the entire lifetime of the stream. While a backup
        // subscription is active no other RPCs may run, and vice versa.
        let guard = Arc::clone(&self.serve_lock).try_write_owned().map_err(|_| {
            Status::resource_exhausted("cannot stream backup while validator is serving requests")
        })?;

        let from = BlockNumber::from(request.block_from);
        let source = BlockStoreSource { block_store: self.block_store.clone() };
        let stream = run_stream(from, self.committed_tip.subscribe(), source).map(move |event| {
            // Keep the guard alive for as long as the stream is polled.
            let _guard = &guard;
            event.map_err(subscription_error_to_status)
        });

        Ok(Box::pin(stream))
    }
}

// STREAM
// ================================================================================================

/// Error raised while loading a block from the validator's [`BlockStore`].
#[derive(Debug, thiserror::Error)]
enum BlockSubscriptionError {
    #[error("failed to load block {block_num}")]
    Load {
        block_num: BlockNumber,
        #[source]
        source: std::io::Error,
    },
    #[error("block {0} not found")]
    NotFound(BlockNumber),
}

/// Streams committed blocks from the validator's [`BlockStore`], emitting each as a
/// [`grpc::validator::BlockSubscriptionResponse`].
struct BlockStoreSource {
    block_store: BlockStore,
}

impl SubscriptionSource for BlockStoreSource {
    type Event = grpc::validator::BlockSubscriptionResponse;
    type Error = BlockSubscriptionError;

    async fn fetch(&self, block_num: BlockNumber) -> Result<Vec<u8>, BlockSubscriptionError> {
        self.block_store
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
    ) -> grpc::validator::BlockSubscriptionResponse {
        grpc::validator::BlockSubscriptionResponse {
            block,
            committed_chain_tip: committed_chain_tip.as_u32(),
        }
    }
}

fn subscription_error_to_status(err: SubscriptionStreamError<BlockSubscriptionError>) -> Status {
    match err {
        SubscriptionStreamError::TooSlow => {
            Status::resource_exhausted("subscriber is too slow to keep up with the chain")
        },
        SubscriptionStreamError::Source(BlockSubscriptionError::NotFound(block_num)) => {
            Status::not_found(format!("block {block_num} not found"))
        },
        SubscriptionStreamError::Source(BlockSubscriptionError::Load { block_num, source }) => {
            Status::internal(format!("failed to load block {block_num}: {}", source.as_report()))
        },
    }
}
