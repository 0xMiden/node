use std::sync::Arc;

use miden_node_proto::domain::account::GetAccountRequest;
use miden_node_proto::domain::block::SyncRange;
use miden_node_proto::{DecodeMessage, Verify, generated as proto};
use miden_node_store::{DatabaseError, GetAccountError, State};
use miden_node_utils::grpc::ClientIp;
use miden_node_utils::limiter::QueryParamAccountIdLimit;
use miden_protocol::account::AccountId;
use proto::miden::node::v1::SyncAccountCommitmentsResponse;

use super::error_codes::SyncAccountCommitmentsErrorCode as ErrorCode;
use super::stream_settings::{DB_PAGE_SIZE, SEND_TIMEOUT, STREAM_BUFFER_SIZE};
use super::sync_stream::{Paginator, SyncResponseStream, SyncStream};
use super::{RpcService, check, database_error_to_status};

#[tonic::async_trait]
impl proto::server::miden_node_v1_node_service::SyncAccountCommitments for RpcService {
    type Input = (SyncRange, Vec<AccountId>);
    type Item = SyncAccountCommitmentsResponse;
    type ItemStream = SyncResponseStream<Self::Item>;

    fn decode(
        request: proto::miden::node::v1::SyncAccountCommitmentsRequest,
    ) -> tonic::Result<Self::Input> {
        check::<QueryParamAccountIdLimit>(request.account_ids.len())?;
        let request = request
            .decode_fields()
            .map_err(|err| ErrorCode::DeserializationFailed.status(err.to_string()))?;
        let range = request
            .range
            .verify()
            .map_err(|err| ErrorCode::InvalidRange.status(err.to_string()))?;
        let mut ids = request
            .account_ids
            .verify()
            .map_err(|err| ErrorCode::DeserializationFailed.status(err.to_string()))?;
        ids.sort_unstable();
        ids.dedup();
        Ok((range, ids))
    }
    fn encode(item: Self::Item) -> tonic::Result<Self::Item> {
        Ok(item)
    }
    async fn handle(
        &self,
        (range, ids): Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::ItemStream> {
        let permit = self
            .sync_stream_limiter
            .acquire(ClientIp::from_extensions(extensions))
            .map_err(|err| ErrorCode::ResourceExhausted.status(err.message()))?;
        SyncStream::start(
            AccountPaginator {
                state: Arc::clone(&self.state),
                range,
                ids,
                cursor: None,
                done: false,
            },
            permit,
            STREAM_BUFFER_SIZE,
            SEND_TIMEOUT,
        )
        .await
    }
}

struct AccountPaginator {
    state: Arc<State>,
    range: SyncRange,
    ids: Vec<AccountId>,
    cursor: Option<AccountId>,
    done: bool,
}
#[tonic::async_trait]
impl Paginator for AccountPaginator {
    type Item = SyncAccountCommitmentsResponse;
    async fn load_next_page(&mut self) -> tonic::Result<Option<Vec<Self::Item>>> {
        if self.done {
            return Ok(None);
        }
        let range = self.range.database_range();
        let view = self.state.view();
        let page = view
            .sync_account_commitments_page(
                if range.is_some() { self.ids.clone() } else { vec![] },
                range.unwrap_or(self.range.target..=self.range.target),
                self.cursor,
                DB_PAGE_SIZE,
            )
            .await
            .map_err(|err| match err {
                DatabaseError::RangeBeyondTip(_) => ErrorCode::FutureTarget.status(err.to_string()),
                DatabaseError::BlockPruned { .. } => {
                    ErrorCode::HistoryUnavailable.status(err.to_string())
                },
                _ => database_error_to_status(&err),
            })?;
        let mut values = Vec::with_capacity(page.changes.len());
        for (account_id, last_updated_at) in page.changes {
            let account = view
                .get_account(GetAccountRequest {
                    block_num: Some(self.range.target),
                    account_id,
                    details: None,
                })
                .await
                .map_err(|err| match err {
                    GetAccountError::UnknownBlock(_) => {
                        ErrorCode::FutureTarget.status(err.to_string())
                    },
                    GetAccountError::BlockPruned(_) => {
                        ErrorCode::HistoryUnavailable.status(err.to_string())
                    },
                    _ => super::error_codes::internal_error(err.to_string()),
                })?;
            values.push(SyncAccountCommitmentsResponse {
                last_updated_at: last_updated_at.as_u32(),
                witness: Some(account.witness.into()),
            });
        }
        self.cursor = page.next_cursor;
        self.done = page.next_cursor.is_none();
        Ok((!values.is_empty()).then_some(values))
    }
}
