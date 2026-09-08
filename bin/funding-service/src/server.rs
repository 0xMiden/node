//! The gRPC server.

use std::time::Duration;

use anyhow::Context;
use miden_node_proto::server::funding_service_api;
use miden_node_proto_build::funding_service_api_descriptor;
use miden_node_tracing::grpc::grpc_trace_fn;
use miden_node_tracing::info;
use miden_node_tracing::panic::{CatchPanicLayer, catch_panic_layer_fn};
use miden_node_utils::shutdown::CancellationToken;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic_health::pb::health_server::{Health, HealthServer};
use tonic_reflection::server;
use tower_http::classify::{GrpcCode, GrpcErrorsAsFailures, SharedClassifier};
use tower_http::trace::TraceLayer;

use crate::LOG_TARGET;
use crate::status::StatusSnapshot;

mod status;

// FUNDING SERVICE RPC SERVER
// ================================================================================================

/// The gRPC service of the funding service.
///
/// The handlers do no chain work: `Status` reads the values the status refresher publishes.
pub struct FundingRpcServer {
    status: StatusSnapshot,
    request_timeout: Duration,
}

impl FundingRpcServer {
    pub(crate) fn new(status: StatusSnapshot, request_timeout: Duration) -> Self {
        Self { status, request_timeout }
    }

    /// Starts the gRPC server on the given listener.
    ///
    /// The health service is registered as a liveness signal for the API.
    pub async fn serve(
        self,
        listener: TcpListener,
        health_service: HealthServer<impl Health>,
        shutdown: CancellationToken,
    ) -> anyhow::Result<()> {
        let request_timeout = self.request_timeout;
        let api_service = funding_service_api::service(self);
        let reflection_service = server::Builder::configure()
            .register_file_descriptor_set(funding_service_api_descriptor())
            .register_encoded_file_descriptor_set(tonic_health::pb::FILE_DESCRIPTOR_SET)
            .build_v1()
            .context("failed to build the reflection service")?;

        let endpoint = listener
            .local_addr()
            .context("failed to read the funding service listen address")?;
        info!(
            target: LOG_TARGET,
            "Funding service gRPC API listening",
            service.name = "miden-funding-service",
            service.version = env!("CARGO_PKG_VERSION"),
            funding_service.listen = endpoint.to_string()
        );

        tonic::transport::Server::builder()
            .layer(CatchPanicLayer::custom(catch_panic_layer_fn))
            // A rejected request is the client's problem, not a server failure, so those codes do
            // not mark the span as failed.
            .layer(
                TraceLayer::new(SharedClassifier::new(
                    GrpcErrorsAsFailures::new()
                        .with_success(GrpcCode::InvalidArgument)
                        .with_success(GrpcCode::FailedPrecondition)
                        .with_success(GrpcCode::ResourceExhausted),
                ))
                .make_span_with(grpc_trace_fn),
            )
            .timeout(request_timeout)
            .add_service(api_service)
            .add_service(health_service)
            .add_service(reflection_service)
            .serve_with_incoming_shutdown(
                TcpListenerStream::new(listener),
                shutdown.cancelled_owned(),
            )
            .await
            .context("failed to serve the funding service gRPC API")
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use miden_protocol::asset::FungibleAsset;

    use super::*;

    /// Builds a server for the handler tests.
    pub(crate) fn test_server(max_amount: u64) -> FundingRpcServer {
        let status = StatusSnapshot::new(FungibleAsset::mock_issuer(), max_amount);

        FundingRpcServer::new(status, Duration::from_secs(1))
    }
}
