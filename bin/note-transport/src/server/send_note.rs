use miden_node_proto::DecodeMessage;
use miden_node_proto::errors::ConversionError;
use miden_node_proto::generated::note_transport::{SendNoteRequest, SendNoteResponse};
use miden_node_proto::server::note_transport_api::SendNote;
use miden_node_tracing::miden_instrument;
use tonic::codegen::http::Extensions;
use tonic::metadata::MetadataMap;

use super::{Server, decode_note};
use crate::{COMPONENT, db};

#[tonic::async_trait]
impl SendNote for Server {
    type Input = db::NewNote;
    type Output = ();

    fn decode(request: SendNoteRequest) -> tonic::Result<Self::Input> {
        decode_note(request.decode_fields().map_err(ConversionError::into_status)?.note)
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
        self.store_note(note).await
    }
}
