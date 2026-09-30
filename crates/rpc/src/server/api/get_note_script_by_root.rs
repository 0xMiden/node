use miden_node_proto::{DecodeMessage, generated as proto};
use miden_node_tracing::{debug, miden_instrument, miden_span_record};
use miden_protocol::Word;
use miden_protocol::note::NoteScript;

use super::error_codes::GetNoteScriptByRootErrorCode;
use super::{RpcService, database_error_to_status};
use crate::{COMPONENT, LOG_TARGET};

#[tonic::async_trait]
impl proto::server::miden_node_v1_node_service::GetNoteScriptByRoot for RpcService {
    type Input = Word;
    type Output = Option<NoteScript>;

    fn decode(
        request: proto::miden::node::v1::GetNoteScriptByRootRequest,
    ) -> tonic::Result<Self::Input> {
        Ok(request
            .decode_fields()
            .map_err(|err| {
                GetNoteScriptByRootErrorCode::DeserializationFailed.invalid_argument(err)
            })?
            .root)
    }

    fn encode(
        output: Self::Output,
    ) -> tonic::Result<proto::miden::node::v1::GetNoteScriptByRootResponse> {
        Ok(proto::miden::node::v1::GetNoteScriptByRootResponse { script: output.map(Into::into) })
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
