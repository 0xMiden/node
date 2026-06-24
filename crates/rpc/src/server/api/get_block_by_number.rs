use miden_node_proto::generated as proto;
use miden_protocol::block::BlockNumber;
use tracing::{debug, instrument};

use super::{RpcService, database_error_to_status};
use crate::{COMPONENT, LOG_TARGET};

#[tonic::async_trait]
impl proto::server::rpc_api::GetBlockByNumber for RpcService {
    type Input = proto::blockchain::BlockRequest;
    type Output = proto::blockchain::MaybeBlock;

    fn decode(request: proto::blockchain::BlockRequest) -> tonic::Result<Self::Input> {
        Ok(request)
    }

    fn encode(output: Self::Output) -> tonic::Result<proto::blockchain::MaybeBlock> {
        Ok(output)
    }

    #[instrument(
        target = COMPONENT,
        name = "get_block_by_number",
        skip_all,
        fields(
            block.number = %request.block_num,
        ),
        err,
    )]
    async fn handle(&self, request: Self::Input) -> tonic::Result<Self::Output> {
        debug!(target: LOG_TARGET, ?request, "Getting block by number");

        let block_num = BlockNumber::from(request.block_num);
        let block = self
            .store
            .load_block(block_num)
            .await
            .map_err(|err| database_error_to_status(&err))?;
        let proof = if request.include_proof.unwrap_or_default() {
            self.store
                .load_proof(block_num)
                .await
                .map_err(|err| database_error_to_status(&err))?
        } else {
            None
        };

        Ok(proto::blockchain::MaybeBlock { block, proof })
    }
}
