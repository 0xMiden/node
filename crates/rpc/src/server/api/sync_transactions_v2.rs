use std::sync::Arc;

use miden_node_proto::domain::block::SyncRange;
use miden_node_proto::{DecodeMessage, Verify, generated as proto};
use miden_node_store::{DatabaseError, State, TransactionCursor, TransactionRecord};
use miden_node_tracing::{instrument, miden_span_record};
use miden_node_utils::limiter::QueryParamAccountIdLimit;
use miden_protocol::account::AccountId;

use super::error_codes::SyncTransactionsV2ErrorCode as ErrorCode;
use super::stream_settings::{
    SEND_TIMEOUT,
    TRANSACTION_DB_PAGE_BYTES,
    TRANSACTION_STREAM_BUFFER_SIZE,
};
use super::sync_stream::{Paginator, SyncResponseStream, SyncStream};
use super::{RpcService, check, database_error_to_status};

#[tonic::async_trait]
impl proto::server::miden_node_v2_node_service::SyncTransactions for RpcService {
    type Input = (SyncRange, Vec<AccountId>);
    type Item = TransactionRecord;
    type ItemStream = SyncResponseStream<Self::Item>;

    fn decode(
        request: proto::miden::node::v2::SyncTransactionsRequest,
    ) -> tonic::Result<Self::Input> {
        check::<QueryParamAccountIdLimit>(request.account_ids.len())?;
        let request = request
            .decode_fields()
            .map_err(|err| ErrorCode::DeserializationFailed.invalid_argument(err))?;
        let target = request
            .range
            .verify()
            .map_err(|err| ErrorCode::InvalidRange.invalid_argument(err))?;
        let mut ids = request
            .account_ids
            .verify()
            .map_err(|err| ErrorCode::DeserializationFailed.invalid_argument(err))?;
        ids.sort_unstable();
        ids.dedup();
        Ok((target, ids))
    }

    fn encode(item: Self::Item) -> tonic::Result<proto::miden::node::v2::SyncTransactionsResponse> {
        Ok(proto::miden::node::v2::SyncTransactionsResponse {
            transaction: Some(super::transaction_stream::encode(item)?),
        })
    }

    #[instrument(name = "sync_transactions_v2", err)]
    async fn handle(
        &self,
        (target, ids): Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::ItemStream> {
        miden_span_record!(
            block_range.from = target.from_exclusive,
            block_range.to = target.target,
            account.count = ids.len(),
            account.ids = super::trace_sample(&ids),
        );

        SyncStream::start(
            TransactionPaginator {
                state: Arc::clone(&self.state),
                target,
                ids,
                cursor: None,
                done: false,
            },
            TRANSACTION_STREAM_BUFFER_SIZE,
            SEND_TIMEOUT,
        )
        .await
    }
}

struct TransactionPaginator {
    state: Arc<State>,
    target: SyncRange,
    ids: Vec<AccountId>,
    cursor: Option<TransactionCursor>,
    done: bool,
}

#[tonic::async_trait]
impl Paginator for TransactionPaginator {
    type Item = TransactionRecord;
    async fn load_next_page(&mut self) -> tonic::Result<Option<Vec<Self::Item>>> {
        if self.done {
            return Ok(None);
        }
        let range = self.target.database_range();
        let page = self
            .state
            .view()
            .sync_transactions_v2_page(
                if range.is_some() { self.ids.clone() } else { vec![] },
                range.unwrap_or(self.target.target..=self.target.target),
                self.cursor,
                TRANSACTION_DB_PAGE_BYTES,
            )
            .await
            .map_err(|err| match err {
                DatabaseError::RangeBeyondTip(_) => ErrorCode::FutureTarget.invalid_argument(err),
                _ => database_error_to_status(&err),
            })?;
        self.cursor = page.next_cursor;
        self.done = page.next_cursor.is_none();
        Ok((!page.records.is_empty()).then_some(page.records))
    }
}
