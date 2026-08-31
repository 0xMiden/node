use miden_node_proto::generated as proto;
use miden_node_tracing::{debug, miden_instrument};
use miden_node_utils::grpc::ClientIp;
use miden_protocol::block::BlockNumber;
use miden_protocol::utils::serde::Deserializable;
use miden_protocol::vm::ExecutionProof;

use super::super::{COMPONENT, RpcService};
use super::stream::{StreamItem, SubscriptionStream};
use crate::LOG_TARGET;

#[tonic::async_trait]
impl proto::server::rpc_api::ProofSubscription for RpcService {
    type Input = BlockNumber;
    type Item = StreamItem;
    type ItemStream = SubscriptionStream;

    fn decode(request: proto::rpc::ProofSubscriptionRequest) -> tonic::Result<Self::Input> {
        Ok(BlockNumber::from(request.block_from))
    }

    fn encode(event: Self::Item) -> tonic::Result<proto::rpc::ProofSubscriptionResponse> {
        let proof = ExecutionProof::read_from_bytes(&event.data)
            .map_err(|err| tonic::Status::internal(format!("invalid stored proof: {err}")))?;
        Ok(proto::rpc::ProofSubscriptionResponse {
            block_num: event.block.as_u32(),
            proof: Some(proof.into()),
            proven_chain_tip: event.tip.as_u32(),
        })
    }

    #[miden_instrument(
        target = COMPONENT,
        name = "proof_subscription",
        fields(
            block.from = input,
        ),
        err,
    )]
    async fn handle(
        &self,
        input: Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::ItemStream> {
        let client_ip = ClientIp::from_extensions(extensions);

        debug!(target: LOG_TARGET, "Subscribing to block proofs");

        let from = input;
        SubscriptionStream::proofs(self, from, client_ip)
    }
}
