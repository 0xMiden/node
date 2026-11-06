use miden_node_proto::generated as proto;
use miden_node_tracing::{debug_v2, instrument_v2};
use miden_protocol::block::BlockNumber;
use miden_protocol::vm::ExecutionProof;

use super::super::{RpcService, log_internal_error};
use super::stream::{StreamItem, SubscriptionStream};

#[tonic::async_trait]
impl proto::server::miden_node_v1_node_service::ProofSubscription for RpcService {
    type Input = BlockNumber;
    type Item = StreamItem;
    type ItemStream = SubscriptionStream;

    fn decode(
        request: proto::miden::node::v1::ProofSubscriptionRequest,
    ) -> tonic::Result<Self::Input> {
        Ok(BlockNumber::from(request.block_from))
    }

    fn encode(
        event: Self::Item,
    ) -> tonic::Result<proto::miden::node::v1::ProofSubscriptionResponse> {
        let proof =
            ExecutionProof::read_from_bytes(&event.data).map_err(|err| log_internal_error(&err))?;
        Ok(proto::miden::node::v1::ProofSubscriptionResponse {
            block_num: event.block.as_u32(),
            proof: Some(proof.into()),
            proven_chain_tip: event.tip.as_u32(),
        })
    }

    #[instrument_v2(
        name = "proof_subscription",
        fields(
            block.from = input,
        ),
    )]
    async fn handle(
        &self,
        input: Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::ItemStream> {
        debug_v2!("Subscribing to block proofs");

        let from = input;
        SubscriptionStream::proofs(self, from)
    }
}
