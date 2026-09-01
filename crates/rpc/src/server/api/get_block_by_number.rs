use miden_node_proto::generated as proto;
use miden_node_tracing::{debug, miden_instrument};
use miden_protocol::block::{BlockNumber, SignedBlock};
use miden_protocol::utils::serde::Deserializable;
use miden_protocol::vm::ExecutionProof;
use tonic::Status;

use super::{RpcService, database_error_to_status};
use crate::{COMPONENT, LOG_TARGET};

#[tonic::async_trait]
impl proto::server::rpc_api::GetBlockByNumber for RpcService {
    type Input = proto::rpc::BlockRequest;
    type Output = proto::rpc::MaybeBlock;

    fn decode(request: proto::rpc::BlockRequest) -> tonic::Result<Self::Input> {
        Ok(request)
    }

    fn encode(output: Self::Output) -> tonic::Result<proto::rpc::MaybeBlock> {
        Ok(output)
    }

    #[miden_instrument(
        target = COMPONENT,
        name = "get_block_by_number",
        fields(
            block.number = request.block_num,
            request.include_proof = request.include_proof.unwrap_or_default(),
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
            "Getting block by number",
            block.number = request.block_num,
            request.include_proof = request.include_proof.unwrap_or_default()
        );

        let block_num = BlockNumber::from(request.block_num);
        let block = self
            .state
            .load_block(block_num)
            .await
            .map_err(|err| database_error_to_status(&err))?
            .map(|bytes| {
                SignedBlock::read_from_bytes(&bytes)
                    .map(Into::into)
                    .map_err(|err| Status::internal(format!("invalid stored block: {err}")))
            })
            .transpose()?;
        let proof = if request.include_proof.unwrap_or_default() {
            self.state
                .load_proof(block_num)
                .await
                .map_err(|err| database_error_to_status(&err))?
                .map(|bytes| {
                    ExecutionProof::read_from_bytes(&bytes)
                        .map(Into::into)
                        .map_err(|err| Status::internal(format!("invalid stored proof: {err}")))
                })
                .transpose()?
        } else {
            None
        };

        Ok(proto::rpc::MaybeBlock { block, proof })
    }
}
