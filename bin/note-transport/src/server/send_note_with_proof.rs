use miden_node_proto::errors::conversion_error_to_status;
use miden_node_proto::generated::note_transport::{SendNoteResponse, SendNoteWithProofRequest};
use miden_node_proto::generated::rpc::BlockHeaderByNumberRequest;
use miden_node_proto::server::note_transport_api::SendNoteWithProof;
use miden_node_proto::{BuildUnchecked, DecodeMessage, Verify};
use miden_node_tracing::{error, miden_instrument, miden_span_record};
use miden_protocol::BLOCK_NOTE_TREE_DEPTH;
use miden_protocol::note::NoteInclusionProof;
use tonic::codegen::http::Extensions;
use tonic::metadata::MetadataMap;

use super::{Server, decode_note};
use crate::{COMPONENT, LOG_TARGET, db};

#[tonic::async_trait]
impl SendNoteWithProof for Server {
    type Input = (db::NewNote, NoteInclusionProof);
    type Output = ();

    fn decode(request: SendNoteWithProofRequest) -> tonic::Result<Self::Input> {
        use miden_node_proto::errors::ConversionResultExt;

        let request = request.decode_fields().map_err(conversion_error_to_status)?;
        let note = decode_note(request.note)?;
        let (note_id, proof) = request
            .inclusion_proof
            .verify()
            .context("inclusion_proof")
            .map_err(conversion_error_to_status)?;
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
        use miden_node_proto::errors::ConversionResultExt;

        miden_span_record!(
            note.id = note.header.id(),
            note.tag = note.header.metadata().tag().as_u32(),
            block.number = proof.location().block_num(),
        );

        self.check_note_size(&note)?;

        let mut rpc = self.rpc.clone();
        let response = tokio::time::timeout(
            // Reserve half of the request budget for note validation and storage.
            self.config.grpc.request_timeout / 2,
            rpc.get_block_header_by_number(BlockHeaderByNumberRequest {
                block_num: Some(proof.location().block_num().as_u32()),
                include_mmr_proof: Some(false),
                include_protocol_config: Some(false),
            }),
        )
        .await
        .map_err(|_| tonic::Status::deadline_exceeded("block header lookup timed out"))?
        .map_err(|error| lookup_status(&error))?
        .into_inner();

        let header = response.block_header
            .ok_or_else(|| tonic::Status::failed_precondition("proof block is not available"))?
            .decode_fields()
            // The configured node supplies the canonical header. No parent check is required.
            .and_then(|header| header.build_unchecked().context("block_header"))
            .map_err(|error| {
                error!(error, target: LOG_TARGET, "Invalid node block header");
                tonic::Status::unavailable("node returned an invalid block header")
            })?;
        if header.block_num() != proof.location().block_num() {
            return Err(tonic::Status::unavailable("node returned a different block"));
        }

        proof
            .note_path()
            .verify(
                proof.location().block_note_tree_index().into(),
                note.header.id().as_word(),
                &header.note_root(),
            )
            .map_err(|_| tonic::Status::invalid_argument("note inclusion proof is invalid"))?;

        note.included_in_block = Some(proof.location().block_num());
        self.store_note(note).await
    }
}

fn lookup_status(error: &tonic::Status) -> tonic::Status {
    match error.code() {
        tonic::Code::NotFound => tonic::Status::failed_precondition("proof block is not available"),
        tonic::Code::DeadlineExceeded => {
            tonic::Status::deadline_exceeded("block header lookup timed out")
        },
        _ => {
            error!(error, target: LOG_TARGET, "Block header lookup failed");
            tonic::Status::unavailable("block header lookup failed")
        },
    }
}
