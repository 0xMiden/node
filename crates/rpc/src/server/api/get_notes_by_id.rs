use miden_node_proto::generated as proto;
use miden_node_proto::generated::rpc::CommittedNote;
use miden_node_store::NoteRecord;
use miden_node_tracing::{debug, miden_instrument, miden_span_record};
use miden_node_utils::limiter::QueryParamNoteIdLimit;
use miden_protocol::Word;
use miden_protocol::note::NoteId;
use tonic::Status;

use super::{RpcService, check, database_error_to_status};
use crate::{COMPONENT, LOG_TARGET};

#[tonic::async_trait]
impl proto::server::rpc_api::GetNotesById for RpcService {
    type Input = proto::rpc::NotesByIdRequest;
    type Output = Vec<CommittedNote>;

    fn decode(request: proto::rpc::NotesByIdRequest) -> tonic::Result<Self::Input> {
        Ok(request)
    }

    fn encode(notes: Self::Output) -> tonic::Result<proto::rpc::NotesByIdResponse> {
        Ok(proto::rpc::NotesByIdResponse { notes })
    }

    #[miden_instrument(
        target = COMPONENT,
        name = "get_notes_by_id",
        err,
    )]
    async fn handle(
        &self,
        request: Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::Output> {
        check::<QueryParamNoteIdLimit>(request.note_ids.len())?;

        let note_ids: Vec<Word> = request
            .note_ids
            .into_iter()
            .map(Word::try_from)
            .collect::<Result<_, _>>()
            .map_err(|err| Status::invalid_argument(format!("invalid note ID: {err}")))?;
        let note_ids: Vec<NoteId> = note_ids.into_iter().map(NoteId::from_raw).collect();
        miden_span_record!(
            note.ids = &note_ids[..note_ids.len().min(10)],
            note.count = note_ids.len()
        );
        debug!(
            target: LOG_TARGET,
            "Getting notes by ID",
            note.ids = &note_ids[..note_ids.len().min(10)],
            note.count = note_ids.len()
        );

        let notes = self
            .state
            .view()
            .get_notes_by_id(note_ids)
            .await
            .map_err(|err| database_error_to_status(&err))?
            .into_iter()
            .map(note_record_to_proto)
            .collect();

        Ok(notes)
    }
}

// HELPERS
// ================================================================================================

fn note_record_to_proto(note: NoteRecord) -> proto::rpc::CommittedNote {
    let inclusion_proof = Some(proto::note::NoteInclusionProof {
        note_id: Some(note.note_id.into()),
        block_num: Some(note.block_num.into()),
        note_index_in_block: note.note_index.leaf_index_value().into(),
        inclusion_path: Some(note.inclusion_path.into()),
    });
    let note = Some(proto::note::Note {
        metadata: Some(note.metadata.into()),
        note_details: note.details.map(Into::into),
        note_attachments: Some(note.attachments.into()),
    });
    proto::rpc::CommittedNote { inclusion_proof, note }
}
