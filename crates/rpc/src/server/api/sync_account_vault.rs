use miden_node_proto::decode::{read_account_id, read_block_range};
use miden_node_proto::generated as proto;
use miden_node_utils::tracing::OpenTelemetrySpanExt;
use miden_protocol::Word;
use tonic::Status;
use tracing::{Span, debug};

use super::{
    COMPONENT,
    Finality,
    RpcInvalidBlockRange,
    RpcService,
    database_error_to_status,
    invalid_block_range_to_status,
};

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

    async fn handle(&self, request: Self::Input) -> tonic::Result<Self::Output> {
        let account_id = read_account_id::<proto::rpc::SyncAccountVaultRequest, Status>(
            request.account_id.clone(),
        )?;
        let range = read_block_range::<Status>(request.block_range, "SyncAccountVaultRequest")?;

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
        let chain_tip = self.store.chain_tip(Finality::Committed).await;

        Ok(proto::rpc::SyncAccountVaultResponse {
            pagination_info: Some(proto::rpc::PaginationInfo {
                chain_tip: chain_tip.as_u32(),
                block_num: last_included_block.as_u32(),
            }),
            updates,
        })
    }
}
