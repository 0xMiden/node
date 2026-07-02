use miden_node_proto::generated as proto;
use miden_node_utils::tracing::miden_instrument;
use miden_protocol::block::BlockNumber;
use tracing::debug;

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
        skip_all,
        fields(
            block.number = %request.block_num(),
        ),
        err,
    )]
    async fn handle(&self, request: Self::Input) -> tonic::Result<Self::Output> {
        debug!(target: LOG_TARGET, ?request, "Getting block header by number");

        let block_num = request.block_num.map(BlockNumber::from);
        let (block_header, mmr_proof) = self
            .store
            .get_block_header(block_num, request.include_mmr_proof.unwrap_or(false))
            .await
            .map_err(super::get_block_header_error_to_status)?;

        Ok(proto::rpc::BlockHeaderByNumberResponse {
            block_header: block_header.map(Into::into),
            chain_length: mmr_proof.as_ref().map(|p| p.forest().num_leaves() as u32),
            mmr_path: mmr_proof.map(|p| Into::into(p.merkle_path())),
        })
    }
}
