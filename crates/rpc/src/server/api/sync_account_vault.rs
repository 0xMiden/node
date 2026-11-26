use miden_node_proto::errors::ConversionResultExt;
use miden_node_proto::{DecodeMessage, Verify, generated as proto};
use miden_node_store::DatabaseError;
use miden_node_tracing::{debug, instrument, miden_span_record};
use miden_protocol::Word;

use super::error_codes::SyncAccountVaultErrorCode;
use super::{
    RpcService,
    check_account_sync_range,
    database_error_to_status,
    invalid_block_range_to_status,
};

#[tonic::async_trait]
impl proto::server::miden_node_v1_node_service::SyncAccountVault for RpcService {
    type Input = proto::miden::node::v1::DecodedSyncAccountVaultRequest;
    type Output = proto::miden::node::v1::SyncAccountVaultResponse;

    fn decode(
        request: proto::miden::node::v1::SyncAccountVaultRequest,
    ) -> tonic::Result<Self::Input> {
        request
            .decode_fields()
            .map_err(|err| SyncAccountVaultErrorCode::DeserializationFailed.invalid_argument(err))
    }

    fn encode(
        output: Self::Output,
    ) -> tonic::Result<proto::miden::node::v1::SyncAccountVaultResponse> {
        Ok(output)
    }

    #[instrument(name = "sync_account_vault")]
    async fn handle(
        &self,
        request: Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::Output> {
        let account_id = request.account_id.verify().context("account_id").map_err(|err| {
            SyncAccountVaultErrorCode::DeserializationFailed.invalid_argument(err)
        })?;
        let range = request.block_range;

        miden_span_record!(
            account.id = account_id,
            block_range.from = range.block_from,
            block_range.to = range.block_to
        );

        debug!(
            "Syncing account vault",
            account.id = account_id,
            block_range.from = range.block_from,
            block_range.to = range.block_to
        );

        if !account_id.is_public() {
            return Err(SyncAccountVaultErrorCode::AccountNotPublic
                .invalid_argument(format!("account {account_id} is not public")));
        }
        let block_range = range.verify().map_err(invalid_block_range_to_status)?;
        let block_to = *block_range.end();
        let (chain_tip, page) = self
            .state
            .read(move |view| {
                let chain_tip = view.snapshot.block_num;
                check_account_sync_range(&block_range, chain_tip)?;
                let page = view.tx.select_account_vault_assets(account_id, block_range)?;
                Ok::<_, DatabaseError>((chain_tip, page))
            })
            .await
            .map_err(|err| match err {
                DatabaseError::RangeBeyondTip(_) => {
                    SyncAccountVaultErrorCode::FutureBlock.invalid_argument(err)
                },
                err => database_error_to_status(&err),
            })?;
        let last_included_block = page.last_block_included(block_to);
        let updates = page
            .items
            .into_iter()
            .map(|update| {
                let vault_key: Word = update.vault_key.into();
                proto::miden::node::v1::AccountVaultUpdate {
                    vault_key: Some(vault_key.into()),
                    asset: update.asset.map(Into::into),
                    block_num: update.block_num.as_u32(),
                }
            })
            .collect();

        Ok(proto::miden::node::v1::SyncAccountVaultResponse {
            pagination_info: Some(proto::miden::node::v1::PaginationInfo {
                chain_tip: chain_tip.as_u32(),
                block_num: last_included_block.as_u32(),
            }),
            updates,
        })
    }
}
