use anyhow::Context;
use miden_node_utils::cors::cors_for_grpc_web_layer;
use miden_node_utils::panic::catch_panic_layer_fn;
use miden_node_utils::tracing::grpc::grpc_trace_fn;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic_web::GrpcWebLayer;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::trace::TraceLayer;

use crate::CliArgs;
use crate::generated::api_server::ApiServer;
use crate::server::prover::ProverService;

pub mod prover;
mod status;

impl CliArgs {
    pub async fn serve(&self) -> anyhow::Result<()> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", self.port))
            .await
            .context("failed to bind to gRPC port")?;

        let status_service = status::StatusService::new(self.kind);
        let prover_service = ProverService::new(self.kind);

        // Create a gRPC health reporter.
        let (health_reporter, health_service) = tonic_health::server::health_reporter();

        // Mark the service as serving
        health_reporter.set_serving::<ApiServer<ProverService>>().await;

        tonic::transport::Server::builder()
            .accept_http1(true)
            .layer(CatchPanicLayer::custom(catch_panic_layer_fn))
            .layer(TraceLayer::new_for_grpc().make_span_with(grpc_trace_fn))
            .layer(cors_for_grpc_web_layer())
            .layer(GrpcWebLayer::new())
            .timeout(self.timeout)
            .add_service(prover_service)
            .add_service(status_service)
            .add_service(health_service)
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await?;

        Ok(())
    }
}
