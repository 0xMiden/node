use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use miden_node_proto::{DecodeMessage, Verify, generated as proto};
use miden_node_store::{DatabaseError, State, TransactionRecord};
use miden_node_utils::grpc::ClientIp;
use miden_node_utils::limiter::QueryParamTransactionIdLimit;
use miden_protocol::block::BlockNumber;
use miden_protocol::transaction::TransactionId;
use tokio_stream::wrappers::ReceiverStream;

use super::error_codes::GetTransactionsByIdErrorCode as ErrorCode;
use super::sync_stream::{Paginator, SyncStream};
use super::{RpcService, check, database_error_to_status};

#[tonic::async_trait]
impl proto::server::miden_node_v1_node_service::GetTransactionsById for RpcService {
    type Input = (BlockNumber, Vec<TransactionId>);
    type Item = TransactionRecord;
    type ItemStream = ReceiverStream<tonic::Result<Self::Item>>;
    fn decode(
        request: proto::miden::node::v1::GetTransactionsByIdRequest,
    ) -> tonic::Result<Self::Input> {
        check::<QueryParamTransactionIdLimit>(request.transaction_ids.len())?;
        let request = request
            .decode_fields()
            .map_err(|err| ErrorCode::DeserializationFailed.status(err.to_string()))?;
        let target = request
            .target_block_num
            .map(BlockNumber::from)
            .ok_or_else(|| ErrorCode::MissingTarget.status("transaction target is required"))?;
        let mut ids = request
            .transaction_ids
            .verify()
            .map_err(|err| ErrorCode::DeserializationFailed.status(err.to_string()))?;
        ids.sort_unstable();
        ids.dedup();
        Ok((target, ids))
    }
    fn encode(
        item: Self::Item,
    ) -> tonic::Result<proto::miden::node::v1::GetTransactionsByIdResponse> {
        Ok(proto::miden::node::v1::GetTransactionsByIdResponse {
            transaction: Some(super::transaction_stream::encode(item)?),
        })
    }
    async fn handle(
        &self,
        (target, ids): Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::ItemStream> {
        let permit = self
            .sync_stream_limiter
            .acquire(ClientIp::from_extensions(extensions))
            .map_err(|err| ErrorCode::ResourceExhausted.status(err.message()))?;
        SyncStream::start(
            LookupPaginator {
                state: Arc::clone(&self.state),
                target,
                ids,
                cursor: None,
                done: false,
            },
            permit,
            1,
            Duration::from_secs(10),
        )
        .await
    }
}

struct LookupPaginator {
    state: Arc<State>,
    target: BlockNumber,
    ids: Vec<TransactionId>,
    cursor: Option<TransactionId>,
    done: bool,
}
#[tonic::async_trait]
impl Paginator for LookupPaginator {
    type Item = TransactionRecord;
    async fn load_next_page(&mut self) -> tonic::Result<Option<Vec<Self::Item>>> {
        if self.done {
            return Ok(None);
        }
        let page = self
            .state
            .view()
            .get_transactions_by_id_page(
                self.ids.clone(),
                self.target,
                self.cursor,
                NonZeroUsize::MIN,
            )
            .await
            .map_err(|err| match err {
                DatabaseError::RangeBeyondTip(_) => ErrorCode::FutureTarget.status(err.to_string()),
                _ => database_error_to_status(&err),
            })?;
        self.cursor = page.next_cursor;
        self.done = page.next_cursor.is_none();
        Ok((!page.records.is_empty()).then_some(page.records))
    }
}
