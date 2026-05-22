use anyhow::Context;
use miden_node_proto::generated::note::NoteId;
use miden_node_proto::generated::ntx_builder::api_server;
use miden_node_proto::generated::rpc;
use miden_node_proto_build::ntx_builder_api_descriptor;
use miden_node_utils::panic::{CatchPanicLayer, catch_panic_layer_fn};
use miden_node_utils::tracing::grpc::grpc_trace_fn;
use miden_protocol::Word;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status};
use tonic_reflection::server;
use tower_http::trace::TraceLayer;

use crate::COMPONENT;
use crate::db::Db;

// NTX BUILDER RPC SERVER
// ================================================================================================

/// gRPC server for the network transaction builder.
///
/// Exposes endpoints for querying network note status, useful for debugging
/// network notes that fail to be consumed.
pub struct NtxBuilderRpcServer {
    db: Db,
    max_note_attempts: usize,
}

impl NtxBuilderRpcServer {
    pub fn new(db: Db, max_note_attempts: usize) -> Self {
        Self { db, max_note_attempts }
    }

    /// Starts the gRPC server on the given listener.
    pub async fn serve(self, listener: TcpListener) -> anyhow::Result<()> {
        let api_service = api_server::ApiServer::new(self);
        let reflection_service = server::Builder::configure()
            .register_file_descriptor_set(ntx_builder_api_descriptor())
            .build_v1()
            .context("failed to build reflection service")?;

        tracing::info!(
            target: COMPONENT,
            endpoint = ?listener.local_addr(),
            "NTX builder gRPC server initialized",
        );

        tonic::transport::Server::builder()
            .layer(CatchPanicLayer::custom(catch_panic_layer_fn))
            .layer(TraceLayer::new_for_grpc().make_span_with(grpc_trace_fn))
            .add_service(api_service)
            .add_service(reflection_service)
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .context("failed to serve NTX builder gRPC API")
    }
}

#[tonic::async_trait]
impl api_server::Api for NtxBuilderRpcServer {
    #[expect(clippy::cast_sign_loss)]
    async fn get_network_note_status(
        &self,
        request: Request<NoteId>,
    ) -> Result<Response<rpc::GetNetworkNoteStatusResponse>, Status> {
        let note_id_proto = request.into_inner();

        let note_id_digest: Word = note_id_proto
            .id
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("missing note ID digest"))?
            .try_into()
            .map_err(|_| Status::invalid_argument("invalid note ID digest"))?;

        let note_id = miden_protocol::note::NoteId::from_raw(note_id_digest);

        let row = self.db.get_note_status(note_id).await.map_err(|err| {
            tracing::error!(err = %err, "failed to query note status from DB");
            Status::internal("database error")
        })?;

        let Some(row) = row else {
            return Err(Status::not_found("note not found in ntx-builder database"));
        };

        let status = derive_status(
            row.committed_at.is_some(),
            row.attempt_count as usize,
            self.max_note_attempts,
        );

        let response = rpc::GetNetworkNoteStatusResponse {
            status: status.into(),
            last_error: row.last_error,
            attempt_count: row.attempt_count as u32,
            last_attempt_block_num: row.last_attempt.map(|v| v as u32),
        };

        Ok(Response::new(response))
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
    use miden_node_proto::generated::rpc::NetworkNoteStatus;

    use super::*;

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
