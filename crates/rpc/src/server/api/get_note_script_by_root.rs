use miden_node_proto::generated as proto;
use miden_node_tracing::{debug, miden_instrument, miden_span_record};
use miden_protocol::Word;
use miden_protocol::note::NoteScript;

use super::{RpcService, database_error_to_status};
use crate::{COMPONENT, LOG_TARGET};

#[tonic::async_trait]
impl proto::server::rpc_api::GetNoteScriptByRoot for RpcService {
    type Input = Word;
    type Output = Option<NoteScript>;

    fn decode(request: proto::rpc::NoteScriptByRootRequest) -> tonic::Result<Self::Input> {
        let note_script_root = request
            .root
            .as_ref()
            .ok_or_else(|| tonic::Status::invalid_argument("missing note script root"))?
            .try_into()
            .map_err(|_| tonic::Status::invalid_argument("invalid note script root"))?;

        Ok(note_script_root)
    }

    fn encode(output: Self::Output) -> tonic::Result<proto::rpc::MaybeNoteScript> {
        Ok(proto::rpc::MaybeNoteScript { script: output.map(Into::into) })
    }

    #[miden_instrument(
        target = COMPONENT,
        name = "get_note_script_by_root",
        err,
    )]
    async fn handle(
        &self,
        request: Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::Output> {
        miden_span_record!(script.root = request);

        debug!(
            target: LOG_TARGET,
            "Getting note script by root",
            script.root = request
        );

        let script = self
            .state
            .view()
            .get_note_script_by_root(request)
            .await
            .map_err(|err| database_error_to_status(&err))?;

        Ok(script)
    }
}
