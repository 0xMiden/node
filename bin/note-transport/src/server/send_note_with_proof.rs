use miden_node_proto::errors::ConversionError;
use miden_node_proto::generated::miden::note_transport::v1::{
    SendNoteWithProofRequest,
    SendNoteWithProofResponse,
};
use miden_node_proto::server::miden_note_transport_v1_note_transport_service::SendNoteWithProof;
use miden_node_proto::{DecodeMessage, Verify};
use miden_node_tracing::{miden_instrument, miden_span_record};
use miden_protocol::BLOCK_NOTE_TREE_DEPTH;
use miden_protocol::note::{NoteDetails, NoteHeader, NoteInclusionProof};
use tonic::codegen::http::Extensions;
use tonic::metadata::MetadataMap;

use super::{Server, decode_note};
use crate::{COMPONENT, db};

#[tonic::async_trait]
impl SendNoteWithProof for Server {
    type Input = (NoteHeader, NoteDetails, NoteInclusionProof);
    type Output = ();

    fn decode(request: SendNoteWithProofRequest) -> tonic::Result<Self::Input> {
        use miden_node_proto::errors::ConversionResultExt;

        let request = request.decode_fields().map_err(ConversionError::into_status)?;
        let (header, details) = decode_note(request.note)?;
        let (note_id, proof) = request
            .inclusion_proof
            .verify()
            .context("inclusion_proof")
            .map_err(ConversionError::into_status)?;
        if note_id != header.id() {
            return Err(tonic::Status::invalid_argument("proof note ID does not match the note"));
        }
        if proof.note_path().depth() != BLOCK_NOTE_TREE_DEPTH {
            return Err(tonic::Status::invalid_argument("invalid note proof depth"));
        }
        Ok((header, details, proof))
    }

    fn encode(_: ()) -> tonic::Result<SendNoteWithProofResponse> {
        Ok(SendNoteWithProofResponse {})
    }

    #[miden_instrument(target = COMPONENT, err)]
    async fn handle(
        &self,
        (header, details, proof): Self::Input,
        _: &MetadataMap,
        _: &Extensions,
    ) -> tonic::Result<()> {
        miden_span_record!(
            note.id = header.id(),
            note.tag = header.metadata().tag().as_u32(),
            block.number = proof.location().block_num(),
        );

        self.check_note_size(&header, &details)?;

        let note_root = self.get_note_root(proof.location().block_num()).await?;

        proof
            .note_path()
            .verify(
                proof.location().block_note_tree_index().into(),
                header.id().as_word(),
                &note_root,
            )
            .map_err(|_| tonic::Status::invalid_argument("note inclusion proof is invalid"))?;

        self.store_note(db::NewNote {
            header,
            details,
            committed_in_block: proof.location().block_num(),
        })
        .await
    }
}
