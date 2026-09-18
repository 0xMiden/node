use miden_node_proto::errors::ConversionError;
use miden_node_proto::generated::note_transport::{SendNoteResponse, SendNoteWithProofRequest};
use miden_node_proto::server::note_transport_api::SendNoteWithProof;
use miden_node_proto::{DecodeMessage, Verify};
use miden_node_tracing::{miden_instrument, miden_span_record};
use miden_protocol::BLOCK_NOTE_TREE_DEPTH;
use miden_protocol::note::NoteInclusionProof;
use tonic::codegen::http::Extensions;
use tonic::metadata::MetadataMap;

use super::{Server, decode_note};
use crate::{COMPONENT, db};

#[tonic::async_trait]
impl SendNoteWithProof for Server {
    type Input = (db::NewNote, NoteInclusionProof);
    type Output = ();

    fn decode(request: SendNoteWithProofRequest) -> tonic::Result<Self::Input> {
        use miden_node_proto::errors::ConversionResultExt;

        let request = request.decode_fields().map_err(ConversionError::into_status)?;
        let note = decode_note(request.note)?;
        let (note_id, proof) = request
            .inclusion_proof
            .verify()
            .context("inclusion_proof")
            .map_err(ConversionError::into_status)?;
        if note_id != note.header.id() {
            return Err(tonic::Status::invalid_argument("proof note ID does not match the note"));
        }
        if proof.note_path().depth() != BLOCK_NOTE_TREE_DEPTH {
            return Err(tonic::Status::invalid_argument("invalid note proof depth"));
        }
        Ok((note, proof))
    }

    fn encode(_: ()) -> tonic::Result<SendNoteResponse> {
        Ok(SendNoteResponse {})
    }

    #[miden_instrument(target = COMPONENT, err)]
    async fn handle(
        &self,
        (mut note, proof): Self::Input,
        _: &MetadataMap,
        _: &Extensions,
    ) -> tonic::Result<()> {
        miden_span_record!(
            note.id = note.header.id(),
            note.tag = note.header.metadata().tag().as_u32(),
            block.number = proof.location().block_num(),
        );

        self.check_note_size(&note)?;

        let note_root = self.get_note_root(proof.location().block_num()).await?;

        proof
            .note_path()
            .verify(
                proof.location().block_note_tree_index().into(),
                note.header.id().as_word(),
                &note_root,
            )
            .map_err(|_| tonic::Status::invalid_argument("note inclusion proof is invalid"))?;

        note.included_in_block = Some(proof.location().block_num());
        self.store_note(note).await
    }
}
