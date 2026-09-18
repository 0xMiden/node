use miden_node_proto::generated::note_transport::{
    FetchNotesCursor,
    FetchNotesRequest,
    FetchNotesResponse,
    FetchedNote,
};
use miden_node_proto::server::note_transport_api::FetchNotes;
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
        request.tags.sort_unstable();
        request.tags.dedup();
        Ok(request)
    }

    fn encode(response: Self::Output) -> tonic::Result<FetchNotesResponse> {
        Ok(response)
    }

    #[miden_instrument(target = COMPONENT, err)]
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

        let page = db::fetch_notes(&self.reader, request.tags, cursor)
            .await
            .map_err(storage_status)?;

        let mut cursor = FetchNotesCursor {
            nonce: page.cursor.nonce,
            sequence: cursor.map_or(0, |cursor| cursor.sequence),
        };

        let mut notes = Vec::with_capacity(page.notes.len());
        let mut has_more = page.has_more;

        // Reserve space for a nonzero sequence and a continuation flag.
        let mut response_bytes = FetchNotesResponse {
            notes: vec![],
            cursor: Some(FetchNotesCursor { sequence: u64::MAX, ..cursor }),
            has_more: true,
        }
        .encoded_len();

        for note in page.notes {
            let next_cursor = u64::try_from(note.seq).map_err(|error| {
                error!(error, target: LOG_TARGET, "Invalid stored note cursor");
                tonic::Status::internal("note storage operation failed")
            })?;
            let note = FetchedNote {
                header: Some(note.header.into()),
                details: Some(note.details.into()),
                after_block_num: note.after_block_num.map(Into::into),
                included_in_block: note.included_in_block.map(Into::into),
            };
            let note_bytes = note.encoded_len();
            let field_bytes =
                1 + prost::encoding::encoded_len_varint(note_bytes as u64) + note_bytes;
            if response_bytes + field_bytes > MAX_RESPONSE_BYTES {
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

        debug!(target: LOG_TARGET, "Notes fetched",
            note_transport.returned = notes.len(), note_transport.cursor.sequence = cursor.sequence,
            note_transport.has_more = has_more);

        Ok(FetchNotesResponse { notes, cursor: Some(cursor), has_more })
    }
}
