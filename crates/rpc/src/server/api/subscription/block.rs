use std::net::IpAddr;

use futures::StreamExt;
use miden_node_proto::generated as proto;
use miden_node_utils::grpc::ClientIp;
use miden_node_utils::tracing::OpenTelemetrySpanExt;
use miden_protocol::block::BlockNumber;
use tonic::{Request, Status};
use tracing::{Span, debug};

use super::super::{COMPONENT, RpcService};

pub struct BlockSubscriptionInput {
    request: proto::rpc::BlockSubscriptionRequest,
    client_ip: Option<IpAddr>,
}

#[tonic::async_trait]
impl proto::server::rpc_api::BlockSubscription for RpcService {
    type Input = BlockSubscriptionInput;
    type Item = proto::rpc::BlockSubscriptionResponse;
    type ItemStream = BlockSubscriptionStream;

    fn decode(request: proto::rpc::BlockSubscriptionRequest) -> tonic::Result<Self::Input> {
        Ok(BlockSubscriptionInput { request, client_ip: None })
    }

    fn encode(item: Self::Item) -> tonic::Result<proto::rpc::BlockSubscriptionResponse> {
        Ok(item)
    }

    async fn full(
        &self,
        request: Request<proto::rpc::BlockSubscriptionRequest>,
    ) -> tonic::Result<Self::ItemStream> {
        let client_ip = ClientIp::from_request(&request);
        let mut input = Self::decode(request.into_inner())?;
        input.client_ip = client_ip;
        self.handle(input).await
    }

    async fn handle(&self, input: Self::Input) -> tonic::Result<Self::ItemStream> {
        let BlockSubscriptionInput { request, client_ip } = input;
        Span::current().set_attribute("block.from", request.block_from);

        debug!(target: COMPONENT, ?request);

        let from = BlockNumber::from(request.block_from);
        let stream = self.block_subscription_stream(from, client_ip)?.map(move |event| {
            event.map(|event| proto::rpc::BlockSubscriptionResponse {
                block: event.data,
                committed_chain_tip: event.tip.as_u32(),
            })
        });
        Ok(stream.boxed())
    }
}

type BlockSubscriptionStream = std::pin::Pin<
    Box<
        dyn tonic::codegen::tokio_stream::Stream<
                Item = Result<proto::rpc::BlockSubscriptionResponse, Status>,
            > + Send
            + 'static,
    >,
>;
