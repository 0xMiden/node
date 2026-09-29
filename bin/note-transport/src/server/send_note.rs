use miden_node_proto::errors::ConversionError;
use miden_node_proto::generated::miden::note_transport::v1::{SendNoteRequest, SendNoteResponse};
use miden_node_proto::server::miden_note_transport_v1_note_transport_service::SendNote;
use miden_node_proto::{DecodeMessage, Verify};
use miden_node_tracing::{miden_instrument, miden_span_record};
use tonic::codegen::http::Extensions;
use tonic::metadata::MetadataMap;

use super::{Server, decode_note};
use crate::{COMPONENT, db};

#[tonic::async_trait]
impl SendNote for Server {
    type Input = db::NewNote;
    type Output = ();

    fn decode(request: SendNoteRequest) -> tonic::Result<Self::Input> {
        let request = request.decode_fields().map_err(ConversionError::into_status)?;
        let mut note = decode_note(request.note)?;
        note.after_block_num =
            request.after_block_num.verify().map_err(ConversionError::into_status)?;
        Ok(note)
    }

    fn encode(_: ()) -> tonic::Result<SendNoteResponse> {
        Ok(SendNoteResponse {})
    }

    #[miden_instrument(target = COMPONENT, err)]
    async fn handle(
        &self,
        note: Self::Input,
        _: &MetadataMap,
        _: &Extensions,
    ) -> tonic::Result<()> {
        miden_span_record!(
            note.id = note.header.id(),
            note.tag = note.header.metadata().tag().as_u32(),
            note.after_block_num = note.after_block_num,
        );

        self.store_note(note).await
    }
}
