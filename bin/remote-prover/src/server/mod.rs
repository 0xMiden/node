use std::num::NonZeroUsize;

use anyhow::Context;
use miden_node_utils::cors::cors_for_grpc_web_layer;
use miden_node_utils::panic::catch_panic_layer_fn;
use miden_node_utils::tracing::grpc::grpc_trace_fn;
use proof_kind::ProofKind;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic_web::GrpcWebLayer;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::trace::TraceLayer;

use crate::generated::api_server::ApiServer;
use crate::server::service::ProverService;

mod proof_kind;
mod prover;
mod service;
mod status;

/// Describes the remote-prover server.
///
/// Can be parsed from the command line using [`Config::parse`].
#[derive(clap::Parser)]
pub struct Config {
    /// The port the gRPC server will be hosted on.
    #[arg(long, default_value = "50051", env = "MIDEN_PROVER_PORT")]
    port: u16,
    /// The proof type that the prover will be handling.
    #[arg(long, env = "MIDEN_PROVER_KIND")]
    kind: ProofKind,
    /// Maximum time allowed for a proof request to complete. Once exceeded, the request is
    /// aborted.
    #[arg(long, default_value = "60s", env = "MIDEN_PROVER_TIMEOUT", value_parser = humantime::parse_duration)]
    timeout: std::time::Duration,
    /// Maximum number of concurrent proof requests that the prover will allow.
    ///
    /// Note that the prover only proves one request at a time; the rest are queued. This capacity
    /// is used to limit the number of requests that can be queued at any given time, and includes
    /// the one request that is currently being processed.
    #[arg(long, default_value_t = NonZeroUsize::new(1).unwrap(), env = "MIDEN_PROVER_CAPACITY")]
    capacity: NonZeroUsize,
}

impl Config {
    /// Starts the remote-prover server.
    ///
    /// Note that this function will only return if the server errors.
    pub async fn serve(&self) -> anyhow::Result<()> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", self.port))
            .await
            .context("failed to bind to gRPC port")?;

        let status_service = status::StatusService::new(self.kind);
        let prover_service = ProverService::with_capacity(self.kind, self.capacity);
        let prover_service = ApiServer::new(prover_service);

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
