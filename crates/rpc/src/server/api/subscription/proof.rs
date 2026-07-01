use std::net::IpAddr;
use std::pin::Pin;

use futures::StreamExt;
use miden_node_proto::generated as proto;
use miden_node_utils::grpc::ClientIp;
use miden_node_utils::tracing::OpenTelemetrySpanExt;
use miden_protocol::block::BlockNumber;
use tonic::{Request, Status};
use tracing::{Span, debug};

use super::super::{COMPONENT, RpcService};

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

        let from = BlockNumber::from(request.block_from);

        let stream = self.proof_subscription_stream(from, client_ip)?.map(move |event| {
            event.map(|event| proto::rpc::ProofSubscriptionResponse {
                block_num: event.block.as_u32(),
                proof: event.data,
                proven_chain_tip: event.tip.as_u32(),
            })
        });
        Ok(stream.boxed())
    }
}

type ProofSubscriptionStream = Pin<
    Box<
        dyn tonic::codegen::tokio_stream::Stream<
                Item = Result<proto::rpc::ProofSubscriptionResponse, Status>,
            > + Send
            + 'static,
    >,
>;
