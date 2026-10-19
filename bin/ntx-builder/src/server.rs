use std::time::Duration;

use anyhow::Context;
use miden_node_proto::server::miden_ntx_builder_v1_network_transaction_builder_service;
use miden_node_proto_build::ntx_builder_api_descriptor;
use miden_node_tracing::grpc::grpc_trace_fn;
use miden_node_tracing::info;
use miden_node_tracing::panic::{CatchPanicLayer, catch_panic_layer_fn};
use miden_node_utils::grpc;
use miden_node_utils::shutdown::CancellationToken;
use tokio::net::TcpListener;
use tonic_reflection::server;
use tower_http::trace::TraceLayer;

use crate::LOG_TARGET;
use crate::db::NtxDbReader;

mod get_network_note_status;

// NTX BUILDER RPC SERVER
// ================================================================================================

/// gRPC server for the network transaction builder.
///
/// Exposes endpoints for querying network note status, useful for debugging
/// network notes that fail to be consumed.
pub struct NtxBuilderRpcServer {
    db: NtxDbReader,
    max_note_attempts: usize,
    request_timeout: Duration,
}

impl NtxBuilderRpcServer {
    pub(crate) fn new(
        db: NtxDbReader,
        max_note_attempts: usize,
        request_timeout: Duration,
    ) -> Self {
        Self { db, max_note_attempts, request_timeout }
    }

    /// Starts the gRPC server on the given listener.
    pub async fn serve(
        self,
        listener: TcpListener,
        shutdown: CancellationToken,
    ) -> anyhow::Result<()> {
        let request_timeout = self.request_timeout;
        let api_service = miden_ntx_builder_v1_network_transaction_builder_service::service(self);
        let reflection_service = server::Builder::configure()
            .register_file_descriptor_set(ntx_builder_api_descriptor())
            .build_v1()
            .context("failed to build reflection service")?;

        let endpoint =
            listener.local_addr().context("failed to read NTX builder listen address")?;
        info!(
            target: LOG_TARGET,
            "NTX builder ready",
            service.name = "miden-ntx-builder",
            service.version = env!("CARGO_PKG_VERSION"),
            ntx_builder.listen = endpoint.to_string()
        );

        grpc::server_builder()
            .layer(CatchPanicLayer::custom(catch_panic_layer_fn))
            .layer(TraceLayer::new_for_grpc().make_span_with(grpc_trace_fn))
            .timeout(request_timeout)
            .add_service(api_service)
            .add_service(reflection_service)
            .serve_with_incoming_shutdown(grpc::tcp_incoming(listener), shutdown.cancelled_owned())
            .await
            .context("failed to serve NTX builder gRPC API")
    }
}
