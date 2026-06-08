use miden_node_proto::decode::convert_digests_to_words;
use miden_node_proto::generated as proto;
use miden_node_utils::limiter::QueryParamNoteIdLimit;
use miden_protocol::Word;
use miden_protocol::note::NoteId;
use tonic::Status;
use tracing::debug;

use super::{COMPONENT, RpcService, check, database_error_to_status, note_record_to_proto};

#[tonic::async_trait]
impl proto::server::rpc_api::GetNotesById for RpcService {
    type Input = proto::note::NoteIdList;
    type Output = proto::note::CommittedNoteList;

    fn decode(request: proto::note::NoteIdList) -> tonic::Result<Self::Input> {
        Ok(request)
    }

    fn encode(output: Self::Output) -> tonic::Result<proto::note::CommittedNoteList> {
        Ok(output)
    }

    async fn handle(&self, request: Self::Input) -> tonic::Result<Self::Output> {
        debug!(target: COMPONENT, ?request);

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

        Ok(proto::note::CommittedNoteList { notes })
    }
}
