use anyhow::Context;
use miden_node_proto::generated::note::NoteId;
use miden_node_proto::generated::ntx_builder::{self, api_server};
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
/// Exposes endpoints for querying note execution errors, useful for debugging
/// network notes that fail to be consumed.
pub struct NtxBuilderRpcServer {
    db: Db,
}

impl NtxBuilderRpcServer {
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    /// Starts the gRPC server on the given listener.
    pub async fn serve(self, listener: TcpListener) -> anyhow::Result<()> {
        let api_service = api_server::ApiServer::new(self);
        let reflection_service = server::Builder::configure()
            .register_file_descriptor_set(ntx_builder_api_descriptor())
            .build_v1()
            .context("failed to build reflection service")?;

        let reflection_service_alpha = server::Builder::configure()
            .register_file_descriptor_set(ntx_builder_api_descriptor())
            .build_v1alpha()
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
            .add_service(reflection_service_alpha)
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .context("failed to serve NTX builder gRPC API")
    }
}

#[tonic::async_trait]
impl api_server::Api for NtxBuilderRpcServer {
    #[expect(clippy::cast_sign_loss)]
    async fn get_note_error(
        &self,
        request: Request<NoteId>,
    ) -> Result<Response<ntx_builder::GetNoteErrorResponse>, Status> {
        let note_id_proto = request.into_inner();

        let note_id_digest: Word = note_id_proto
            .id
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("missing note ID digest"))?
            .try_into()
            .map_err(|_| Status::invalid_argument("invalid note ID digest"))?;

        let note_id = miden_protocol::note::NoteId::from_raw(note_id_digest);

        let row = self.db.get_note_error(note_id).await.map_err(|err| {
            tracing::error!(err = %err, "failed to query note error from DB");
            Status::internal("database error")
        })?;

        let Some(row) = row else {
            return Err(Status::not_found("note not found in ntx-builder database"));
        };

        let response = ntx_builder::GetNoteErrorResponse {
            error: row.last_error,
            attempt_count: row.attempt_count as u32,
            last_attempt_block_num: row.last_attempt.map(|v| v as u32),
        };

        Ok(Response::new(response))
    }
}
