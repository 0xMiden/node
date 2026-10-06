use std::sync::Arc;

use miden_node_proto::domain::block::SyncRange;
use miden_node_proto::{DecodeMessage, Verify, generated as proto};
use miden_node_store::{DatabaseError, NullifierCursor, NullifierInfo, State};
use miden_node_utils::limiter::QueryParamNullifierPrefixLimit;
use tracing::miden_instrument;

use super::error_codes::SyncNullifiersV2ErrorCode as ErrorCode;
use super::stream_settings::{DB_PAGE_SIZE, SEND_TIMEOUT, STREAM_BUFFER_SIZE};
use super::sync_stream::{Paginator, SyncResponseStream, SyncStream};
use super::{RpcService, check, database_error_to_status};
use crate::COMPONENT;

#[tonic::async_trait]
impl proto::server::miden_node_v1_node_service::SyncNullifiersV2 for RpcService {
    type Input = (SyncRange, Vec<u16>);
    type Item = NullifierInfo;
    type ItemStream = SyncResponseStream<Self::Item>;

    fn decode(
        request: proto::miden::node::v1::SyncNullifiersV2Request,
    ) -> tonic::Result<Self::Input> {
        check::<QueryParamNullifierPrefixLimit>(request.nullifiers.len())?;
        let request = request
            .decode_fields()
            .map_err(|err| ErrorCode::DeserializationFailed.status(err.to_string()))?;
        let target = request
            .range
            .verify()
            .map_err(|err| ErrorCode::InvalidRange.status(err.to_string()))?;
        if request.prefix_len != 16 {
            return Err(ErrorCode::InvalidPrefixLength.status("only 16-bit prefixes are supported"));
        }
        let mut ids = request
            .nullifiers
            .into_inner()
            .into_iter()
            .map(|prefix| {
                u16::try_from(prefix).map_err(|_| {
                    ErrorCode::DeserializationFailed.status("nullifier prefix exceeds 16 bits")
                })
            })
            .collect::<tonic::Result<Vec<_>>>()?;
        ids.sort_unstable();
        ids.dedup();
        Ok((target, ids))
    }

    fn encode(item: Self::Item) -> tonic::Result<proto::miden::node::v1::SyncNullifiersV2Response> {
        Ok(proto::miden::node::v1::SyncNullifiersV2Response {
            nullifier: Some(item.nullifier.as_word().into()),
            block_num: item.block_num.as_u32(),
        })
    }

    #[miden_instrument(
        target = COMPONENT,
        name = "sync_account_nullifiers_v2",
        err,
    )]
    async fn handle(
        &self,
        (target, ids): Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::ItemStream> {
        SyncStream::start(
            NullifierPaginator {
                state: Arc::clone(&self.state),
                target,
                ids,
                cursor: None,
                done: false,
            },
            STREAM_BUFFER_SIZE,
            SEND_TIMEOUT,
        )
        .await
    }
}

struct NullifierPaginator {
    state: Arc<State>,
    target: SyncRange,
    ids: Vec<u16>,
    cursor: Option<NullifierCursor>,
    done: bool,
}
#[tonic::async_trait]
impl Paginator for NullifierPaginator {
    type Item = NullifierInfo;
    async fn load_next_page(&mut self) -> tonic::Result<Option<Vec<Self::Item>>> {
        if self.done {
            return Ok(None);
        }
        let range = self.target.database_range();
        let page = self
            .state
            .view()
            .sync_nullifiers_v2_page(
                if range.is_some() { self.ids.clone() } else { vec![] },
                range.unwrap_or(self.target.target..=self.target.target),
                self.cursor,
                DB_PAGE_SIZE,
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
