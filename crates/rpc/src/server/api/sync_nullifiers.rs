use miden_node_proto::decode::read_block_range;
use miden_node_proto::generated as proto;
use miden_node_utils::limiter::QueryParamNullifierPrefixLimit;
use tonic::Status;
use tracing::debug;

use super::{
    RpcInvalidBlockRange,
    RpcService,
    check,
    database_error_to_status,
    invalid_block_range_to_status,
};
use crate::{COMPONENT, LOG_TARGET};

#[tonic::async_trait]
impl proto::server::rpc_api::SyncNullifiers for RpcService {
    type Input = proto::rpc::SyncNullifiersRequest;
    type Output = proto::rpc::SyncNullifiersResponse;

    fn decode(request: proto::rpc::SyncNullifiersRequest) -> tonic::Result<Self::Input> {
        Ok(request)
    }

    fn encode(output: Self::Output) -> tonic::Result<proto::rpc::SyncNullifiersResponse> {
        Ok(output)
    }

    #[miden_node_utils::tracing::miden_instrument(
        target = COMPONENT,
        name = "sync_nullifiers",
        skip_all,
        err,
    )]
    async fn handle(&self, request: Self::Input) -> tonic::Result<Self::Output> {
        tracing::trace!(target: LOG_TARGET, ?request);

        let range = read_block_range::<Status>(request.block_range, "SyncNullifiersRequest")?;

        miden_node_utils::tracing::miden_span_record!(
            block_range.from = range.block_from,
            block_range.to = range.block_to,
        );

        debug!(target: LOG_TARGET, "Syncing nullifiers");

        check::<QueryParamNullifierPrefixLimit>(request.nullifiers.len())?;

        if request.prefix_len != 16 {
            return Err(Status::invalid_argument(format!(
                "unsupported prefix length: {} (only 16-bit prefixes are supported)",
                request.prefix_len
            )));
        }
        let block_range = range
            .into_inclusive_range::<RpcInvalidBlockRange>()
            .map_err(invalid_block_range_to_status)?;
        let chain_tip = self.range_bounds_check(&block_range).await?;

        let (nullifiers, block_num) = self
            .store
            .sync_nullifiers(request.prefix_len, request.nullifiers, block_range)
            .await
            .map_err(|err| database_error_to_status(&err))?;
        let nullifiers = nullifiers
            .into_iter()
            .map(|nullifier_info| proto::rpc::sync_nullifiers_response::NullifierUpdate {
                nullifier: Some(nullifier_info.nullifier.into()),
                block_num: nullifier_info.block_num.as_u32(),
            })
            .collect();

        Ok(proto::rpc::SyncNullifiersResponse {
            pagination_info: Some(proto::rpc::PaginationInfo {
                chain_tip: chain_tip.as_u32(),
                block_num: block_num.as_u32(),
            }),
            nullifiers,
        })
    }
}
