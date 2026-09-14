use miden_node_proto::errors::{ConversionResultExt, conversion_error_to_status};
use miden_node_proto::{DecodeMessage, Verify, generated as proto};
use miden_node_tracing::{debug, miden_instrument, miden_span_record};
use tonic::Status;

use super::{
    RpcInvalidBlockRange,
    RpcService,
    database_error_to_status,
    invalid_block_range_to_status,
};
use crate::{COMPONENT, LOG_TARGET};

#[tonic::async_trait]
impl proto::server::rpc_api::SyncAccountStorageMaps for RpcService {
    type Input = proto::rpc::DecodedSyncAccountStorageMapsRequest;
    type Output = proto::rpc::SyncAccountStorageMapsResponse;

    fn decode(request: proto::rpc::SyncAccountStorageMapsRequest) -> tonic::Result<Self::Input> {
        request.decode_fields().map_err(conversion_error_to_status)
    }

    fn encode(output: Self::Output) -> tonic::Result<proto::rpc::SyncAccountStorageMapsResponse> {
        Ok(output)
    }

    #[miden_instrument(
        target = COMPONENT,
        name = "sync_account_storage_maps",
        err,
    )]
    async fn handle(
        &self,
        request: Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::Output> {
        let account_id = request
            .account_id
            .verify()
            .context("account_id")
            .map_err(conversion_error_to_status)?;
        let range = request.block_range;

        miden_span_record!(
            account.id = account_id,
            block_range.from = range.block_from,
            block_range.to = range.block_to
        );

        debug!(
            target: LOG_TARGET,
            "Syncing account storage maps",
            account.id = account_id,
            block_range.from = range.block_from,
            block_range.to = range.block_to
        );

        if !account_id.is_public() {
            return Err(Status::invalid_argument(format!("account {account_id} is not public")));
        }
        let block_range = range
            .verify()
            .map_err(RpcInvalidBlockRange::from)
            .map_err(invalid_block_range_to_status)?;
        let (chain_tip, storage_maps_page) = self
            .state
            .with_view(async |view| {
                view.sync_account_storage_maps(account_id, block_range)
                    .await
                    .map(|page| (view.tip(), page))
                    .map_err(|err| database_error_to_status(&err))
            })
            .await?;
        let updates = storage_maps_page
            .values
            .into_iter()
            .map(|map_value| proto::rpc::StorageMapUpdate {
                slot_name: map_value.slot_name.to_string(),
                key: Some(map_value.key.as_word().into()),
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
