use miden_node_proto::decode::convert_digests_to_words;
use miden_node_proto::generated as proto;
use miden_node_proto::generated::note::CommittedNote;
use miden_node_store::NoteRecord;
use miden_node_utils::limiter::QueryParamNoteIdLimit;
use miden_protocol::Word;
use miden_protocol::note::NoteId;
use miden_protocol::utils::serde::Serializable;
use tonic::Status;

use super::{RpcService, check, database_error_to_status};
use crate::{COMPONENT, LOG_TARGET};

#[tonic::async_trait]
impl proto::server::rpc_api::GetNotesById for RpcService {
    type Input = proto::note::NoteIdList;
    type Output = Vec<CommittedNote>;

    fn decode(request: proto::note::NoteIdList) -> tonic::Result<Self::Input> {
        Ok(request)
    }

    fn encode(notes: Self::Output) -> tonic::Result<proto::note::CommittedNoteList> {
        Ok(proto::note::CommittedNoteList { notes })
    }

    #[miden_node_utils::tracing::miden_instrument(
        target = COMPONENT,
        name = "get_notes_by_id",
        skip_all,
        err,
    )]
    async fn handle(&self, request: Self::Input) -> tonic::Result<Self::Output> {
        tracing::trace!(target: LOG_TARGET, ?request);

        check::<QueryParamNoteIdLimit>(request.ids.len())?;

        let note_ids: Vec<Word> = convert_digests_to_words::<Status, _>(request.ids)?;
        let note_ids: Vec<NoteId> = note_ids.into_iter().map(NoteId::from_raw).collect();

        let notes = self
            .store
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

fn note_record_to_proto(note: NoteRecord) -> proto::note::CommittedNote {
    let inclusion_proof = Some(proto::note::NoteInclusionInBlockProof {
        note_id: Some(note.note_id.into()),
        block_num: note.block_num.as_u32(),
        note_index_in_block: note.note_index.leaf_index_value().into(),
        inclusion_path: Some(note.inclusion_path.into()),
    });
    let note = Some(proto::note::Note {
        metadata: Some(note.metadata.into()),
        details: note.details.map(|details| details.to_bytes()),
        attachments: note.attachments.to_bytes(),
    });
    proto::note::CommittedNote { inclusion_proof, note }
}
