use anyhow::Context;
use miden_node_proto::server::ntx_builder_api;
use miden_node_proto_build::ntx_builder_api_descriptor;
use miden_node_utils::panic::{CatchPanicLayer, catch_panic_layer_fn};
use miden_node_utils::shutdown::CancellationToken;
use miden_node_utils::tracing::grpc::grpc_trace_fn;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic_reflection::server;
use tower_http::trace::TraceLayer;

use crate::COMPONENT;
use crate::db::Db;

mod get_network_note_status;

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
    pub async fn serve(
        self,
        listener: TcpListener,
        shutdown: CancellationToken,
    ) -> anyhow::Result<()> {
        let api_service = ntx_builder_api::service(self);
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
            .serve_with_incoming_shutdown(
                TcpListenerStream::new(listener),
                shutdown.cancelled_owned(),
            )
            .await
            .context("failed to serve NTX builder gRPC API")
    }
}
