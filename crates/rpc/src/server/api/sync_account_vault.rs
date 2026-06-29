use miden_node_proto::decode::{read_account_id, read_block_range};
use miden_node_proto::generated as proto;
use miden_protocol::Word;
use tonic::Status;

use super::{
    RpcInvalidBlockRange,
    RpcService,
    database_error_to_status,
    invalid_block_range_to_status,
};
use crate::{COMPONENT, LOG_TARGET};

#[tonic::async_trait]
impl proto::server::rpc_api::SyncAccountVault for RpcService {
    type Input = proto::rpc::SyncAccountVaultRequest;
    type Output = proto::rpc::SyncAccountVaultResponse;

    fn decode(request: proto::rpc::SyncAccountVaultRequest) -> tonic::Result<Self::Input> {
        Ok(request)
    }

    fn encode(output: Self::Output) -> tonic::Result<proto::rpc::SyncAccountVaultResponse> {
        Ok(output)
    }

    #[miden_node_utils::tracing::miden_instrument(
        target = COMPONENT,
        name = "sync_account_vault",
        skip_all,
        err,
    )]
    async fn handle(&self, request: Self::Input) -> tonic::Result<Self::Output> {
        tracing::trace!(target: LOG_TARGET, ?request);

        let account_id = read_account_id::<proto::rpc::SyncAccountVaultRequest, Status>(
            request.account_id.clone(),
        )?;
        let range = read_block_range::<Status>(request.block_range, "SyncAccountVaultRequest")?;

        miden_node_utils::tracing::miden_span_record!(
            account.id = %account_id,
            block_range.from = range.block_from,
            block_range.to = range.block_to,
        );

        tracing::debug!(target: LOG_TARGET, "Syncing account vault");

        if !account_id.is_public() {
            return Err(Status::invalid_argument(format!("account {account_id} is not public")));
        }
        let block_range = range
            .into_inclusive_range::<RpcInvalidBlockRange>()
            .map_err(invalid_block_range_to_status)?;
        let chain_tip = self.range_bounds_check(&block_range).await?;
        let (last_included_block, updates) = self
            .store
            .sync_account_vault(account_id, block_range)
            .await
            .map_err(|err| database_error_to_status(&err))?;
        let updates = updates
            .into_iter()
            .map(|update| {
                let vault_key: Word = update.vault_key.into();
                proto::rpc::AccountVaultUpdate {
                    vault_key: Some(vault_key.into()),
                    asset: update.asset.map(Into::into),
                    block_num: update.block_num.as_u32(),
                }
            })
            .collect();

        Ok(proto::rpc::SyncAccountVaultResponse {
            pagination_info: Some(proto::rpc::PaginationInfo {
                chain_tip: chain_tip.as_u32(),
                block_num: last_included_block.as_u32(),
            }),
            updates,
        })
    }
}
