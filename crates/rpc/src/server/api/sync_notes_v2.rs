use std::sync::Arc;

use miden_node_proto::domain::block::SyncRange;
use miden_node_proto::{DecodeMessage, Verify, generated as proto};
use miden_node_store::{NoteSyncCursor, NoteSyncError, State};
use miden_node_tracing::{instrument, miden_span_record};
use miden_node_utils::limiter::QueryParamNoteTagLimit;
use miden_protocol::block::BlockNumber;
use proto::miden::node::v2::sync_notes_response::Item;
use proto::miden::node::v2::{NoteBlockStart, SyncNotesResponse};
use tonic::Status;

use super::error_codes::{SyncNotesV2ErrorCode as ErrorCode, internal_error};
use super::stream_settings::{DB_PAGE_SIZE, SEND_TIMEOUT, STREAM_BUFFER_SIZE};
use super::sync_notes::note_sync_record_to_proto;
use super::sync_stream::{Paginator, SyncPage, SyncResponseStream, SyncStream};
use super::{RpcService, check, database_error_to_status};

#[tonic::async_trait]
impl proto::server::miden_node_v2_node_service::SyncNotes for RpcService {
    type Input = (SyncRange, Vec<u32>);
    type Item = SyncNotesResponse;
    type ItemStream = SyncResponseStream<Self::Item>;

    fn decode(request: proto::miden::node::v2::SyncNotesRequest) -> tonic::Result<Self::Input> {
        check::<QueryParamNoteTagLimit>(request.note_tags.len())?;
        let request = request
            .decode_fields()
            .map_err(|err| ErrorCode::DeserializationFailed.invalid_argument(err))?;
        let range = request
            .range
            .verify()
            .map_err(|err| ErrorCode::InvalidRange.invalid_argument(err))?;
        let mut tags = request.note_tags.into_inner();
        tags.sort_unstable();
        tags.dedup();
        Ok((range, tags))
    }

    fn encode(item: Self::Item) -> tonic::Result<SyncNotesResponse> {
        Ok(item)
    }

    #[instrument(name = "sync_notes_v2", err)]
    async fn handle(
        &self,
        (range, tags): Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::ItemStream> {
        miden_span_record!(
            block_range.from = range.from_exclusive,
            block_range.to = range.target,
            note.tag.count = tags.len(),
            note.tags = super::trace_sample(&tags),
        );

        SyncStream::start(
            NotePaginator {
                state: Arc::clone(&self.state),
                range,
                tags,
                cursor: None,
                last_block: None,
                done: false,
            },
            STREAM_BUFFER_SIZE,
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
    type Item = SyncNotesResponse;
    async fn load_next_page(&mut self) -> tonic::Result<Option<SyncPage<Self::Item>>> {
        if self.done {
            return Ok(None);
        }
        let range = self.range.database_range();
        let is_first_page = self.cursor.is_none();
        let page = self
            .state
            .view()
            .sync_notes_v2_page(
                if range.is_some() { self.tags.clone() } else { vec![] },
                range.unwrap_or(self.range.target..=self.range.target),
                self.cursor,
                DB_PAGE_SIZE,
            )
            .await
            .map_err(note_stream_error_to_status)?;
        self.cursor = page.next_cursor;
        self.done = page.next_cursor.is_none();
        let mut frames = Vec::new();
        for (update, proof) in page.updates {
            let block = update.block_header.block_num();
            if self.last_block != Some(block) {
                frames.push(SyncNotesResponse {
                    item: Some(Item::Block(NoteBlockStart {
                        block_header: Some(update.block_header.into()),
                        mmr_path: Some(proof.merkle_path().clone().into()),
                    })),
                });
                self.last_block = Some(block);
            }
            frames.extend(update.notes.into_iter().map(|note| SyncNotesResponse {
                item: Some(Item::Note(note_sync_record_to_proto(note).into())),
            }));
        }
        if is_first_page && self.done && frames.is_empty() {
            return Ok(None);
        }
        SyncPage::new(frames).map(Some)
    }
}

/// Maps a note page failure to the status the client receives.
///
/// Notes are never pruned, so a missing block header or MMR opening for a block at or below the
/// target is a fault in the node and not something the client can correct.
fn note_stream_error_to_status(err: NoteSyncError) -> Status {
    let message = err.to_string();
    match err {
        NoteSyncError::RangeBeyondTip(_) => ErrorCode::FutureTarget.invalid_argument(message),
        NoteSyncError::TargetOverflow => ErrorCode::InvalidRange.invalid_argument(message),
        NoteSyncError::DatabaseError(err) => database_error_to_status(&err),
        _ => internal_error(message),
    }
}

#[cfg(test)]
mod tests {
    use miden_node_store::{DatabaseError, NoteSyncError};
    use miden_protocol::crypto::merkle::mmr::MmrError;

    use super::note_stream_error_to_status;

    /// A block header missing from the store is a node fault, so the client must not be told to
    /// change its request.
    #[test]
    fn missing_block_header_is_an_internal_error() {
        let status = note_stream_error_to_status(NoteSyncError::DatabaseError(
            DatabaseError::DataCorrupted("block header 1 is missing for a stored note".into()),
        ));

        assert_eq!(status.code(), tonic::Code::Internal);
        assert_eq!(status.details(), &[0]);
    }

    #[test]
    fn mmr_opening_failure_is_an_internal_error() {
        let status =
            note_stream_error_to_status(NoteSyncError::MmrError(MmrError::PositionNotFound(1)));

        assert_eq!(status.code(), tonic::Code::Internal);
        assert_eq!(status.details(), &[0]);
    }
}
