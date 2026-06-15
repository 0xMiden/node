use std::sync::Arc;

use miden_node_proto::generated as proto;
use miden_node_utils::tracing::OpenTelemetrySpanExt;
use miden_protocol::block::BlockNumber;
use tokio_stream::StreamExt;
use tonic::Status;
use tracing::{Span, debug};

use super::{
    COMPONENT,
    GuardedStream,
    ProofSubscriptionStream,
    RpcService,
    proof_subscription_error_to_status,
};

#[tonic::async_trait]
impl proto::server::rpc_api::ProofSubscription for RpcService {
    type Input = proto::rpc::ProofSubscriptionRequest;
    type Item = proto::rpc::ProofSubscriptionResponse;
    type ItemStream = ProofSubscriptionStream;

    fn decode(request: proto::rpc::ProofSubscriptionRequest) -> tonic::Result<Self::Input> {
        Ok(request)
    }

    fn encode(item: Self::Item) -> tonic::Result<proto::rpc::ProofSubscriptionResponse> {
        Ok(item)
    }

    async fn handle(&self, request: Self::Input) -> tonic::Result<Self::ItemStream> {
        Span::current().set_attribute("block.from", request.block_from);

        debug!(target: COMPONENT, ?request);

        let permit = Arc::clone(&self.proof_subscription_semaphore)
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("maximum proof subscriptions reached"))?;

        let from = BlockNumber::from(request.block_from);
        let stream = self.store.proof_subscription(from).map(|event| {
            event
                .map(|event| proto::rpc::ProofSubscriptionResponse {
                    block_num: event.block_num.as_u32(),
                    proof: event.proof,
                    proven_chain_tip: event.proven_chain_tip.as_u32(),
                })
                .map_err(proof_subscription_error_to_status)
        });
        let stream: Self::ItemStream = Box::pin(GuardedStream::new(Box::pin(stream), permit));
        Ok(stream)
    }
}
