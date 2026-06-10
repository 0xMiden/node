use miden_node_proto::decode::read_root;
use miden_node_proto::generated as proto;
use tonic::Status;
use tracing::debug;

use super::{COMPONENT, RpcService, database_error_to_status};

#[tonic::async_trait]
impl proto::server::rpc_api::GetNoteScriptByRoot for RpcService {
    type Input = proto::note::NoteScriptRoot;
    type Output = proto::rpc::MaybeNoteScript;

    fn decode(request: proto::note::NoteScriptRoot) -> tonic::Result<Self::Input> {
        Ok(request)
    }

    fn encode(output: Self::Output) -> tonic::Result<proto::rpc::MaybeNoteScript> {
        Ok(output)
    }

    async fn handle(&self, request: Self::Input) -> tonic::Result<Self::Output> {
        debug!(target: COMPONENT, ?request);

        let root = read_root::<Status>(request.root, "NoteScriptRoot")?;
        let script = self
            .store
            .get_note_script_by_root(root)
            .await
            .map_err(|err| database_error_to_status(&err))?;

        Ok(proto::rpc::MaybeNoteScript { script: script.map(Into::into) })
    }
}
