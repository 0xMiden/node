use std::sync::Arc;

use miden_node_proto::generated as proto;
use miden_node_utils::tracing::OpenTelemetrySpanExt;
use miden_protocol::block::BlockNumber;
use tokio_stream::StreamExt;
use tonic::Status;
use tracing::{Span, debug};

use super::{
    BlockSubscriptionStream,
    COMPONENT,
    GuardedStream,
    RpcService,
    state_subscription_error_to_status,
};

#[tonic::async_trait]
impl proto::server::rpc_api::BlockSubscription for RpcService {
    type Input = proto::rpc::BlockSubscriptionRequest;
    type Item = proto::rpc::BlockSubscriptionResponse;
    type ItemStream = BlockSubscriptionStream;

    fn decode(request: proto::rpc::BlockSubscriptionRequest) -> tonic::Result<Self::Input> {
        Ok(request)
    }

    fn encode(item: Self::Item) -> tonic::Result<proto::rpc::BlockSubscriptionResponse> {
        Ok(item)
    }

    async fn handle(&self, request: Self::Input) -> tonic::Result<Self::ItemStream> {
        Span::current().set_attribute("block.from", request.block_from);

        debug!(target: COMPONENT, ?request);

        let permit = Arc::clone(&self.block_subscription_semaphore)
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("maximum block subscriptions reached"))?;

        let from = BlockNumber::from(request.block_from);
        let stream = self.store.block_subscription(from).map(|event| {
            event
                .map(|event| proto::rpc::BlockSubscriptionResponse {
                    block: event.block,
                    committed_chain_tip: event.committed_chain_tip.as_u32(),
                })
                .map_err(state_subscription_error_to_status)
        });
        let stream: Self::ItemStream = Box::pin(GuardedStream::new(Box::pin(stream), permit));
        Ok(stream)
    }
}
