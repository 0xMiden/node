use std::net::IpAddr;
use std::pin::Pin;

use futures::StreamExt;
use miden_node_proto::generated as proto;
use miden_node_utils::grpc::ClientIp;
use miden_node_utils::tracing::OpenTelemetrySpanExt;
use miden_protocol::block::BlockNumber;
use tonic::{Request, Status};
use tracing::{Span, debug, instrument};

use super::super::{COMPONENT, RpcService};
use super::stream::{StreamItem, SubscriptionStream};
use crate::LOG_TARGET;

pub struct ProofSubscriptionInput {
    request: proto::rpc::ProofSubscriptionRequest,
    client_ip: Option<IpAddr>,
}

#[tonic::async_trait]
impl proto::server::rpc_api::ProofSubscription for RpcService {
    type Input = ProofSubscriptionInput;
    type Item = StreamItem;
    type ItemStream = SubscriptionStream;

    fn decode(request: proto::rpc::ProofSubscriptionRequest) -> tonic::Result<Self::Input> {
        Ok(ProofSubscriptionInput { request, client_ip: None })
    }

    fn encode(event: Self::Item) -> tonic::Result<proto::rpc::ProofSubscriptionResponse> {
        Ok(proto::rpc::ProofSubscriptionResponse {
            block_num: event.block.as_u32(),
            proof: event.data,
            proven_chain_tip: event.tip.as_u32(),
        })
    }

    async fn full(
        &self,
        request: Request<proto::rpc::ProofSubscriptionRequest>,
    ) -> tonic::Result<ProofSubscriptionResponseStream> {
        let client_ip = ClientIp::from_request(&request);
        let mut input = Self::decode(request.into_inner())?;
        input.client_ip = client_ip;
        let stream = self.handle(input).await?;
        Ok(Box::pin(stream.map(|item| item.and_then(Self::encode))))
    }

    #[instrument(
        target = COMPONENT,
        name = "proof_subscription",
        skip_all,
        fields(
            block.from = %input.request.block_from,
        ),
        err,
    )]
    async fn handle(&self, input: Self::Input) -> tonic::Result<Self::ItemStream> {
        let ProofSubscriptionInput { request, client_ip } = input;
        Span::current().set_attribute("block.from", request.block_from);

        debug!(target: LOG_TARGET, "Subscribing to block proofs");

        let from = BlockNumber::from(request.block_from);

        SubscriptionStream::proofs(self, from, client_ip)
    }
}

type ProofSubscriptionResponseStream = Pin<
    Box<
        dyn tonic::codegen::tokio_stream::Stream<
                Item = Result<proto::rpc::ProofSubscriptionResponse, Status>,
            > + Send
            + 'static,
    >,
>;
