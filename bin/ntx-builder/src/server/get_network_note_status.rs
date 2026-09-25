use miden_node_proto::generated::{self as grpc, rpc};
use miden_node_tracing::error;
use miden_protocol::Word;

use super::NtxBuilderRpcServer;
use crate::{COMPONENT, LOG_TARGET};

#[tonic::async_trait]
impl grpc::server::ntx_builder_api::GetNetworkNoteStatus for NtxBuilderRpcServer {
    type Input = miden_protocol::note::NoteId;
    type Output = grpc::ntx_builder::GetNetworkNoteStatusResponse;

    fn decode(
        request: grpc::ntx_builder::GetNetworkNoteStatusRequest,
    ) -> tonic::Result<Self::Input> {
        let note_id_digest: Word = request
            .note_id
            .as_ref()
            .ok_or_else(|| tonic::Status::invalid_argument("missing note ID"))?
            .id
            .as_ref()
            .ok_or_else(|| tonic::Status::invalid_argument("missing note ID digest"))?
            .try_into()
            .map_err(|_| tonic::Status::invalid_argument("invalid note ID digest"))?;

        Ok(miden_protocol::note::NoteId::from_raw(note_id_digest))
    }

    #[miden_node_tracing::miden_instrument(
        target = COMPONENT,
        name = "get_network_note_status",
        fields (
            note.id = note_id,
        ),
        err,
    )]
    async fn handle(
        &self,
        note_id: Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::Output> {
        let row = self.db.get_note_status(note_id).await.map_err(|err| {
            error!(
                &err,
                target: LOG_TARGET,
                "Failed to query note status from DB"
            );
            tonic::Status::internal("database error")
        })?;

        let Some(row) = row else {
            return Err(tonic::Status::not_found("note not found in ntx-builder database"));
        };

        let attempt_count = usize::try_from(row.attempt_count)
            .map_err(|_| tonic::Status::internal("invalid attempt count in database"))?;
        let response_attempt_count = u32::try_from(row.attempt_count)
            .map_err(|_| tonic::Status::internal("invalid attempt count in database"))?;
        let last_attempt_block_num =
            row.last_attempt.map(u32::try_from).transpose().map_err(|_| {
                tonic::Status::internal("invalid last attempt block number in database")
            })?;

        let status =
            derive_status(row.committed_at.is_some(), attempt_count, self.max_note_attempts);

        Ok(grpc::ntx_builder::GetNetworkNoteStatusResponse {
            status: status.into(),
            last_error: row.last_error,
            attempt_count: response_attempt_count,
            last_attempt_block_num,
        })
    }

    fn encode(
        output: Self::Output,
    ) -> tonic::Result<grpc::ntx_builder::GetNetworkNoteStatusResponse> {
        Ok(output)
    }
}

// HELPERS
// ================================================================================================

/// Derives the lifecycle status of a network note from its DB state.
fn derive_status(
    is_committed: bool,
    attempt_count: usize,
    max_note_attempts: usize,
) -> rpc::NetworkNoteStatus {
    if is_committed {
        rpc::NetworkNoteStatus::NullifierCommitted
    } else if attempt_count >= max_note_attempts {
        rpc::NetworkNoteStatus::Discarded
    } else {
        rpc::NetworkNoteStatus::Pending
    }
}

#[cfg(test)]
mod tests {
    use miden_node_proto::generated::note::NoteId;
    use miden_node_proto::generated::rpc::NetworkNoteStatus;
    use miden_node_proto::generated::server::ntx_builder_api::GetNetworkNoteStatus;

    use super::*;

    #[test]
    fn decode_rejects_missing_note_id() {
        let error = NtxBuilderRpcServer::decode(grpc::ntx_builder::GetNetworkNoteStatusRequest {
            note_id: None,
        })
        .unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn decode_preserves_note_id() {
        let note_id = miden_protocol::note::NoteId::from_raw(Word::from([1u32, 2, 3, 4]));
        let decoded = NtxBuilderRpcServer::decode(grpc::ntx_builder::GetNetworkNoteStatusRequest {
            note_id: Some(note_id.as_word().into()),
        })
        .unwrap();
        assert_eq!(decoded, note_id);
    }

    #[test]
    fn decode_note_id_rejects_missing_digest() {
        let err = NtxBuilderRpcServer::decode(grpc::ntx_builder::GetNetworkNoteStatusRequest {
            note_id: Some(NoteId { id: None }),
        })
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert_eq!(err.message(), "missing note ID digest");
    }

    #[test]
    fn derive_status_pending() {
        assert_eq!(derive_status(false, 0, 30), NetworkNoteStatus::Pending);
        assert_eq!(derive_status(false, 15, 30), NetworkNoteStatus::Pending);
        assert_eq!(derive_status(false, 29, 30), NetworkNoteStatus::Pending);
    }

    #[test]
    fn derive_status_discarded() {
        assert_eq!(derive_status(false, 30, 30), NetworkNoteStatus::Discarded);
        assert_eq!(derive_status(false, 100, 30), NetworkNoteStatus::Discarded);
    }

    #[test]
    fn derive_status_committed() {
        // committed takes precedence over attempt count
        assert_eq!(derive_status(true, 0, 30), NetworkNoteStatus::NullifierCommitted);
        assert_eq!(derive_status(true, 30, 30), NetworkNoteStatus::NullifierCommitted);
    }
}
