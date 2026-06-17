use miden_node_proto::decode::{read_account_id, read_block_range};
use miden_node_proto::generated as proto;
use miden_node_utils::tracing::OpenTelemetrySpanExt;
use tonic::Status;
use tracing::{Span, debug};

use super::{
    COMPONENT,
    RpcInvalidBlockRange,
    RpcService,
    database_error_to_status,
    invalid_block_range_to_status,
};

#[tonic::async_trait]
impl proto::server::rpc_api::SyncAccountStorageMaps for RpcService {
    type Input = proto::rpc::SyncAccountStorageMapsRequest;
    type Output = proto::rpc::SyncAccountStorageMapsResponse;

    fn decode(request: proto::rpc::SyncAccountStorageMapsRequest) -> tonic::Result<Self::Input> {
        Ok(request)
    }

    fn encode(output: Self::Output) -> tonic::Result<proto::rpc::SyncAccountStorageMapsResponse> {
        Ok(output)
    }

    async fn handle(&self, request: Self::Input) -> tonic::Result<Self::Output> {
        let account_id = read_account_id::<proto::rpc::SyncAccountStorageMapsRequest, Status>(
            request.account_id.clone(),
        )?;
        let range =
            read_block_range::<Status>(request.block_range, "SyncAccountStorageMapsRequest")?;

        let span = Span::current();
        span.set_attribute("account.id", account_id);
        span.set_attribute("block_range.from", range.block_from);
        span.set_attribute("block_range.to", range.block_to);

        debug!(target: COMPONENT, ?request);

        if !account_id.is_public() {
            return Err(Status::invalid_argument(format!("account {account_id} is not public")));
        }
        let block_range = range
            .into_inclusive_range::<RpcInvalidBlockRange>()
            .map_err(invalid_block_range_to_status)?;
        let chain_tip = self.range_bounds_check(&block_range).await?;
        let storage_maps_page = self
            .store
            .sync_account_storage_maps(account_id, block_range)
            .await
            .map_err(|err| database_error_to_status(&err))?;
        let updates = storage_maps_page
            .values
            .into_iter()
            .map(|map_value| proto::rpc::StorageMapUpdate {
                slot_name: map_value.slot_name.to_string(),
                key: Some(map_value.key.into()),
                value: Some(map_value.value.into()),
                block_num: map_value.block_num.as_u32(),
            })
            .collect();

        Ok(proto::rpc::SyncAccountStorageMapsResponse {
            pagination_info: Some(proto::rpc::PaginationInfo {
                chain_tip: chain_tip.as_u32(),
                block_num: storage_maps_page.last_block_included.as_u32(),
            }),
            updates,
        })
    }
}
