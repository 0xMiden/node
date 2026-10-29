use miden_node_proto::generated::miden::note_transport::v1::{
    FetchNotesCursor,
    FetchNotesRequest,
    FetchNotesResponse,
    FetchedNote,
};
use miden_node_proto::server::miden_note_transport_v1_note_transport_service::FetchNotes;
use miden_node_tracing::{debug, error, miden_instrument, miden_span_record};
use prost::Message;
use tonic::codegen::http::Extensions;
use tonic::metadata::MetadataMap;

use super::{Server, storage_status};
use crate::{COMPONENT, LOG_TARGET, db};

// Keep responses within the default gRPC client decoding limit.
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

#[tonic::async_trait]
impl FetchNotes for Server {
    type Input = FetchNotesRequest;
    type Output = FetchNotesResponse;

    fn decode(mut request: FetchNotesRequest) -> tonic::Result<Self::Input> {
        if request.tags.len() > 128 {
            return Err(tonic::Status::invalid_argument("at most 128 tags are allowed"));
        }
        if request.cursor.is_some_and(|cursor| cursor.sequence > i64::MAX as u64) {
            return Err(tonic::Status::invalid_argument("invalid cursor"));
        }
        if request.sync_to.is_some_and(|bound| bound.sequence > i64::MAX as u64) {
            return Err(tonic::Status::invalid_argument("invalid sync range"));
        }
        request.tags.sort_unstable();
        request.tags.dedup();
        Ok(request)
    }

    fn encode(response: Self::Output) -> tonic::Result<FetchNotesResponse> {
        Ok(response)
    }

    #[miden_instrument(target = COMPONENT)]
    async fn handle(
        &self,
        request: Self::Input,
        _: &MetadataMap,
        _: &Extensions,
    ) -> tonic::Result<Self::Output> {
        miden_span_record!(
            note.tags = request.tags.as_slice(),
            note.tag.count = request.tags.len(),
            note_transport.cursor.sequence = request.cursor.map(|cursor| cursor.sequence),
            note_transport.cursor.nonce = request.cursor.map(|cursor| cursor.nonce),
        );

        let cursor = request.cursor.map(|cursor| db::Cursor {
            nonce: cursor.nonce,
            sequence: cursor.sequence,
        });

        let sync_to = request.sync_to.map(|bound| db::Cursor {
            nonce: bound.nonce,
            sequence: bound.sequence,
        });
        let page = db::fetch_notes(&self.reader, request.tags, cursor, sync_to)
            .await
            .map_err(storage_status)?;
        let response = encode_page(page, cursor, MAX_RESPONSE_BYTES)?;
        debug!(target: LOG_TARGET, "Notes fetched",
            note_transport.returned = response.notes.len(),
            note_transport.cursor.sequence = response.cursor.expect("response cursor is present").sequence,
            note_transport.has_more = response.has_more);
        Ok(response)
    }
}

/// Encodes a bounded page without advancing past notes excluded by the response limit.
pub(super) fn encode_page(
    page: db::FetchPage,
    request_cursor: Option<db::Cursor>,
    max_response_bytes: usize,
) -> tonic::Result<FetchNotesResponse> {
    let mut cursor = FetchNotesCursor {
        nonce: page.cursor.nonce,
        sequence: request_cursor.map_or(0, |cursor| cursor.sequence),
    };
    let sync_to = FetchNotesCursor {
        nonce: page.sync_to.nonce,
        sequence: page.sync_to.sequence,
    };
    let mut has_more = page.has_more;
    let mut notes = Vec::with_capacity(page.notes.len());
    let mut response_bytes = FetchNotesResponse {
        notes: vec![],
        cursor: Some(FetchNotesCursor { sequence: u64::MAX, ..cursor }),
        has_more: true,
        sync_to: Some(sync_to),
    }
    .encoded_len();
    for stored in page.notes {
        let next_cursor = u64::try_from(stored.seq).map_err(|error| {
            error!(error, target: LOG_TARGET, "Invalid stored note cursor");
            tonic::Status::internal("note storage operation failed")
        })?;
        let note = FetchedNote {
            header: Some(stored.header.into()),
            details: Some(stored.details.into()),
            committed_in_block: Some(stored.committed_in_block.into()),
        };
        let note_bytes = note.encoded_len();
        let field_bytes = 1 + prost::encoding::encoded_len_varint(note_bytes as u64) + note_bytes;
        if response_bytes + field_bytes > max_response_bytes {
            if notes.is_empty() {
                return Err(tonic::Status::resource_exhausted(
                    "stored note exceeds the response limit",
                ));
            }
            has_more = true;
            break;
        }
        response_bytes += field_bytes;
        cursor.sequence = next_cursor;
        notes.push(note);
    }
    Ok(FetchNotesResponse {
        notes,
        cursor: Some(cursor),
        has_more,
        sync_to: Some(sync_to),
    })
}
