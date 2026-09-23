use miden_node_proto::generated as proto;
use miden_node_tracing::{debug, miden_instrument};
use miden_protocol::block::BlockNumber;

use super::{COMPONENT, RpcService};
use crate::LOG_TARGET;

#[tonic::async_trait]
impl proto::server::rpc_api::GetBlockHeaderByNumber for RpcService {
    type Input = proto::rpc::BlockHeaderByNumberRequest;
    type Output = proto::rpc::BlockHeaderByNumberResponse;

    fn decode(request: proto::rpc::BlockHeaderByNumberRequest) -> tonic::Result<Self::Input> {
        Ok(request)
    }

    fn encode(output: Self::Output) -> tonic::Result<proto::rpc::BlockHeaderByNumberResponse> {
        Ok(output)
    }

    #[miden_instrument(
        target = COMPONENT,
        name = "get_block_header_by_number",
        fields(
            block.number = request.block_num(),
            request.include_mmr_proof = request.include_mmr_proof.unwrap_or_default(),
        ),
        err,
    )]
    async fn handle(
        &self,
        request: Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::Output> {
        debug!(
            target: LOG_TARGET,
            "Getting block header by number",
            block.number = request.block_num(),
            request.include_mmr_proof = request.include_mmr_proof.unwrap_or_default()
        );

        let block_num = request.block_num.map(BlockNumber::from);
        let view = self.state.view();
        let (block_header, mmr_proof) = view
            .get_block_header(block_num, request.include_mmr_proof.unwrap_or(false))
            .await
            .map_err(super::get_block_header_error_to_status)?;

        let protocol_config = match block_header.as_ref() {
            Some(header) if request.include_protocol_config.unwrap_or(false) => {
                Some(super::load_protocol_config(&view, header).await?.into())
            },
            _ => None,
        };

        Ok(proto::rpc::BlockHeaderByNumberResponse {
            protocol_config,
            block_header: block_header.map(Into::into),
            chain_length: mmr_proof.as_ref().map(|p| p.forest().num_leaves() as u32),
            mmr_path: mmr_proof.map(|p| Into::into(p.merkle_path())),
        })
    }
}
