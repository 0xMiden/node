use miden_node_proto::decode::{read_account_ids, read_block_range};
use miden_node_proto::generated as proto;
use miden_node_utils::limiter::QueryParamAccountIdLimit;
use miden_node_utils::tracing::OpenTelemetrySpanExt;
use tonic::Status;
use tracing::{Span, debug};

use super::{
    COMPONENT,
    Finality,
    RpcInvalidBlockRange,
    RpcService,
    check,
    database_error_to_status,
    invalid_block_range_to_status,
    transaction_record_to_proto,
};

#[tonic::async_trait]
impl proto::server::rpc_api::SyncTransactions for RpcService {
    type Input = proto::rpc::SyncTransactionsRequest;
    type Output = proto::rpc::SyncTransactionsResponse;

    fn decode(request: proto::rpc::SyncTransactionsRequest) -> tonic::Result<Self::Input> {
        Ok(request)
    }

    fn encode(output: Self::Output) -> tonic::Result<proto::rpc::SyncTransactionsResponse> {
        Ok(output)
    }

    async fn handle(&self, request: Self::Input) -> tonic::Result<Self::Output> {
        let range = read_block_range::<Status>(request.block_range, "SyncTransactionsRequest")?;
        let n_accounts = request.account_ids.len();
        let account_ids =
            read_account_ids::<Status, _>(request.account_ids.iter().take(10).cloned())?;

        let span = Span::current();
        span.set_attribute("block_range.from", range.block_from);
        span.set_attribute("block_range.to", range.block_to);
        span.set_attribute("account.ids", format!("{account_ids:?}").as_str());
        span.set_attribute("account.ids.count", n_accounts);

        debug!(target: COMPONENT, ?request);

        check::<QueryParamAccountIdLimit>(request.account_ids.len())?;

        let block_range = range
            .into_inclusive_range::<RpcInvalidBlockRange>()
            .map_err(invalid_block_range_to_status)?;
        let account_ids = read_account_ids::<Status, _>(request.account_ids)?;
        let (last_block_included, transaction_records_db) = self
            .store
            .sync_transactions(account_ids, block_range)
            .await
            .map_err(|err| database_error_to_status(&err))?;
        let transactions =
            transaction_records_db.into_iter().map(transaction_record_to_proto).collect();
        let chain_tip = self.store.chain_tip(Finality::Committed).await;

        Ok(proto::rpc::SyncTransactionsResponse {
            pagination_info: Some(proto::rpc::PaginationInfo {
                chain_tip: chain_tip.as_u32(),
                block_num: last_block_included.as_u32(),
            }),
            transactions,
        })
    }
}
