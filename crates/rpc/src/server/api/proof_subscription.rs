use std::net::IpAddr;
use std::sync::Arc;

use miden_node_proto::generated as proto;
use miden_node_store::state::StateSubscriptionError;
use miden_node_utils::{grpc::ClientIp, tracing::OpenTelemetrySpanExt};
use miden_protocol::block::BlockNumber;
use tokio_stream::StreamExt;
use tonic::{Request, Status};
use tracing::{Span, debug};

use super::{
    COMPONENT,
    GuardedStream,
    ProofSubscriptionStream,
    RpcService,
    state_subscription_error_to_status,
    subscription_ban_status,
};

pub struct ProofSubscriptionInput {
    request: proto::rpc::ProofSubscriptionRequest,
    client_ip: Option<IpAddr>,
}

#[tonic::async_trait]
impl proto::server::rpc_api::ProofSubscription for RpcService {
    type Input = ProofSubscriptionInput;
    type Item = proto::rpc::ProofSubscriptionResponse;
    type ItemStream = ProofSubscriptionStream;

    fn decode(request: proto::rpc::ProofSubscriptionRequest) -> tonic::Result<Self::Input> {
        Ok(ProofSubscriptionInput { request, client_ip: None })
    }

    fn encode(item: Self::Item) -> tonic::Result<proto::rpc::ProofSubscriptionResponse> {
        Ok(item)
    }

    async fn full(
        &self,
        request: Request<proto::rpc::ProofSubscriptionRequest>,
    ) -> tonic::Result<Self::ItemStream> {
        let client_ip = ClientIp::from_request(&request);
        let mut input = Self::decode(request.into_inner())?;
        input.client_ip = client_ip;
        self.handle(input).await
    }

    async fn handle(&self, input: Self::Input) -> tonic::Result<Self::ItemStream> {
        let ProofSubscriptionInput { request, client_ip } = input;
        Span::current().set_attribute("block.from", request.block_from);

        debug!(target: COMPONENT, ?request);

        // Reject clients that were recently disconnected for being too slow.
        if let Some(remaining) = client_ip.and_then(|ip| self.subscription_ban.remaining(ip)) {
            return Err(subscription_ban_status(remaining));
        }

        let permit = Arc::clone(&self.proof_subscription_semaphore)
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("maximum proof subscriptions reached"))?;

        let from = BlockNumber::from(request.block_from);
        let ban = Arc::clone(&self.subscription_ban);
        let stream = self.store.proof_subscription(from).map(move |event| {
            event
                .map(|event| proto::rpc::ProofSubscriptionResponse {
                    block_num: event.block_num.as_u32(),
                    proof: event.proof,
                    proven_chain_tip: event.proven_chain_tip.as_u32(),
                })
                .map_err(|err| {
                    // Ban slow subscribers so they cannot immediately reconnect and re-stall.
                    if matches!(err, StateSubscriptionError::TooSlow) {
                        if let Some(ip) = client_ip {
                            ban.ban(ip);
                        }
                    }
                    state_subscription_error_to_status(err)
                })
        });
        let stream: Self::ItemStream = Box::pin(GuardedStream::new(Box::pin(stream), permit));
        Ok(stream)
    }
}
