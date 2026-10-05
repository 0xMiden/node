use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use miden_node_proto::domain::block::SyncRange;
use miden_node_proto::{DecodeMessage, Verify, generated as proto};
use miden_node_store::{DatabaseError, NoteSyncCursor, NoteSyncError, State};
use miden_node_utils::grpc::ClientIp;
use miden_node_utils::limiter::QueryParamNoteTagLimit;
use miden_protocol::block::BlockNumber;
use proto::miden::node::v1::sync_notes_v2_response::Item;
use proto::miden::node::v1::{NoteBlockStart, SyncNotesV2Response};

use super::error_codes::SyncNotesV2ErrorCode as ErrorCode;
use super::sync_notes::note_sync_record_to_proto;
use super::sync_stream::{Paginator, SyncResponseStream, SyncStream};
use super::{RpcService, check, database_error_to_status};

const PAGE_SIZE: NonZeroUsize = NonZeroUsize::new(256).unwrap();
const BUFFER_SIZE: usize = 32;
const SEND_TIMEOUT: Duration = Duration::from_secs(10);

#[tonic::async_trait]
impl proto::server::miden_node_v1_node_service::SyncNotesV2 for RpcService {
    type Input = (SyncRange, Vec<u32>);
    type Item = SyncNotesV2Response;
    type ItemStream = SyncResponseStream<Self::Item>;

    fn decode(request: proto::miden::node::v1::SyncNotesV2Request) -> tonic::Result<Self::Input> {
        check::<QueryParamNoteTagLimit>(request.note_tags.len())?;
        let request = request
            .decode_fields()
            .map_err(|err| ErrorCode::DeserializationFailed.status(err.to_string()))?;
        let range = request
            .range
            .verify()
            .map_err(|err| ErrorCode::InvalidRange.status(err.to_string()))?;
        let mut tags = request.note_tags.into_inner();
        tags.sort_unstable();
        tags.dedup();
        Ok((range, tags))
    }

    fn encode(item: Self::Item) -> tonic::Result<SyncNotesV2Response> {
        Ok(item)
    }

    async fn handle(
        &self,
        (range, tags): Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::ItemStream> {
        let permit = self
            .sync_stream_limiter
            .acquire(ClientIp::from_extensions(extensions))
            .map_err(|err| ErrorCode::ResourceExhausted.status(err.message()))?;
        SyncStream::start(
            NotePaginator {
                state: Arc::clone(&self.state),
                range,
                tags,
                cursor: None,
                last_block: None,
                done: false,
            },
            permit,
            BUFFER_SIZE,
            SEND_TIMEOUT,
        )
        .await
    }
}

struct NotePaginator {
    state: Arc<State>,
    range: SyncRange,
    tags: Vec<u32>,
    cursor: Option<NoteSyncCursor>,
    last_block: Option<BlockNumber>,
    done: bool,
}

#[tonic::async_trait]
impl Paginator for NotePaginator {
    type Item = SyncNotesV2Response;
    async fn load_next_page(&mut self) -> tonic::Result<Option<Vec<Self::Item>>> {
        if self.done {
            return Ok(None);
        }
        let range = self.range.database_range();
        let page = self
            .state
            .view()
            .sync_notes_v2_page(
                if range.is_some() { self.tags.clone() } else { vec![] },
                range.unwrap_or(self.range.target..=self.range.target),
                self.cursor,
                PAGE_SIZE,
            )
            .await
            .map_err(|err| match err {
                NoteSyncError::RangeBeyondTip(_) => ErrorCode::FutureTarget.status(err.to_string()),
                NoteSyncError::TargetOverflow => ErrorCode::InvalidRange.status(err.to_string()),
                NoteSyncError::MmrError(_)
                | NoteSyncError::EmptyBlockHeadersTable
                | NoteSyncError::DatabaseError(DatabaseError::BlockPruned { .. }) => {
                    ErrorCode::HistoryUnavailable.status(err.to_string())
                },
                NoteSyncError::DatabaseError(err) => database_error_to_status(&err),
                _ => super::error_codes::internal_error(err.to_string()),
            })?;
        self.cursor = page.next_cursor;
        self.done = page.next_cursor.is_none();
        let mut frames = Vec::new();
        for (update, proof) in page.updates {
            let block = update.block_header.block_num();
            if self.last_block != Some(block) {
                frames.push(SyncNotesV2Response {
                    item: Some(Item::Block(NoteBlockStart {
                        block_header: Some(update.block_header.into()),
                        mmr_path: Some(proof.merkle_path().clone().into()),
                    })),
                });
                self.last_block = Some(block);
            }
            frames.extend(update.notes.into_iter().map(|note| SyncNotesV2Response {
                item: Some(Item::Note(note_sync_record_to_proto(note))),
            }));
        }
        Ok((!frames.is_empty()).then_some(frames))
    }
}
