use miden_node_proto::errors::ConversionResultExt;
use miden_node_proto::{DecodeMessage, Verify, generated as proto};
use miden_node_store::{DatabaseError, default_storage_map_entries_limit};
use miden_node_tracing::{debug, instrument, miden_span_record};

use super::error_codes::SyncAccountStorageMapsErrorCode;
use super::{
    RpcService,
    check_account_sync_range,
    database_error_to_status,
    invalid_block_range_to_status,
};

#[tonic::async_trait]
impl proto::server::miden_node_v1_node_service::SyncAccountStorageMaps for RpcService {
    type Input = proto::miden::node::v1::DecodedSyncAccountStorageMapsRequest;
    type Output = proto::miden::node::v1::SyncAccountStorageMapsResponse;

    fn decode(
        request: proto::miden::node::v1::SyncAccountStorageMapsRequest,
    ) -> tonic::Result<Self::Input> {
        request.decode_fields().map_err(|err| {
            SyncAccountStorageMapsErrorCode::DeserializationFailed.invalid_argument(err)
        })
    }

    fn encode(
        output: Self::Output,
    ) -> tonic::Result<proto::miden::node::v1::SyncAccountStorageMapsResponse> {
        Ok(output)
    }

    #[instrument(name = "sync_account_storage_maps")]
    async fn handle(
        &self,
        request: Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::Output> {
        let account_id = request.account_id.verify().context("account_id").map_err(|err| {
            SyncAccountStorageMapsErrorCode::DeserializationFailed.invalid_argument(err)
        })?;
        let range = request.block_range;

        miden_span_record!(
            account.id = account_id,
            block_range.from = range.block_from,
            block_range.to = range.block_to
        );

        debug!(
            "Syncing account storage maps",
            account.id = account_id,
            block_range.from = range.block_from,
            block_range.to = range.block_to
        );

        if !account_id.is_public() {
            return Err(SyncAccountStorageMapsErrorCode::AccountNotPublic
                .invalid_argument(format!("account {account_id} is not public")));
        }
        let block_range = range.verify().map_err(invalid_block_range_to_status)?;
        let block_to = *block_range.end();
        let (chain_tip, page) = self
            .state
            .read(move |view| {
                let chain_tip = view.snapshot.block_num;
                check_account_sync_range(&block_range, chain_tip)?;
                let page = view.tx.select_account_storage_map_values_paged(
                    account_id,
                    block_range,
                    default_storage_map_entries_limit(),
                )?;
                Ok::<_, DatabaseError>((chain_tip, page))
            })
            .await
            .map_err(|err| match err {
                DatabaseError::RangeBeyondTip(_) => {
                    SyncAccountStorageMapsErrorCode::FutureBlock.invalid_argument(err)
                },
                err => database_error_to_status(&err),
            })?;
        let last_block_included = page.last_block_included(block_to);
        let updates = page
            .items
            .into_iter()
            .map(|map_value| proto::miden::node::v1::StorageMapUpdate {
                slot_name: map_value.slot_name.to_string(),
                key: Some(map_value.key.as_word().into()),
                value: Some(map_value.value.into()),
                block_num: map_value.block_num.as_u32(),
            })
            .collect();

        Ok(proto::miden::node::v1::SyncAccountStorageMapsResponse {
            pagination_info: Some(proto::miden::node::v1::PaginationInfo {
                chain_tip: chain_tip.as_u32(),
                block_num: last_block_included.as_u32(),
            }),
            updates,
        })
    }
}
