use miden_node_proto::errors::ConversionResultExt;
use miden_node_proto::{DecodeMessage, Verify, generated as proto};
use miden_node_store::DatabaseError;
use miden_node_tracing::{debug, miden_instrument, miden_span_record};
use miden_protocol::Word;

use super::error_codes::SyncAccountVaultErrorCode;
use super::{RpcService, database_error_to_status, invalid_block_range_to_status};
use crate::{COMPONENT, LOG_TARGET};

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

    #[miden_instrument(
        target = COMPONENT,
        name = "sync_account_vault",
        err,
    )]
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
            target: LOG_TARGET,
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
        let (chain_tip, (last_included_block, updates)) = self
            .state
            .with_view(async |view| {
                view.sync_account_vault(account_id, block_range)
                    .await
                    .map(|updates| (view.tip(), updates))
                    .map_err(|err| match err {
                        DatabaseError::RangeBeyondTip(_) => {
                            SyncAccountVaultErrorCode::FutureBlock.invalid_argument(err)
                        },
                        err => database_error_to_status(&err),
                    })
            })
            .await?;
        let updates = updates
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
