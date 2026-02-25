use std::num::NonZeroUsize;

use anyhow::Context;
use miden_node_utils::cors::cors_for_grpc_web_layer;
use miden_node_utils::panic::catch_panic_layer_fn;
use miden_node_utils::tracing::grpc::grpc_trace_fn;
use proof_kind::ProofKind;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::TcpListenerStream;
use tonic_web::GrpcWebLayer;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::trace::TraceLayer;

use crate::generated::api_server::ApiServer;
use crate::server::service::ProverService;

pub mod proof_kind;
pub mod prover;
pub mod service;
pub mod status;

#[cfg(test)]
mod tests;

/// A gRPC server providing a proving service for the Miden blockchain.
#[derive(clap::Parser)]
pub struct Server {
    /// The port the gRPC server will be hosted on.
    #[arg(long, default_value = "50051", env = "MIDEN_PROVER_PORT")]
    port: u16,
    /// The proof type that the prover will be handling.
    #[arg(long, value_enum, env = "MIDEN_PROVER_KIND")]
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

impl Server {
    /// Spawns the prover server, returning its handle and the port it is listening on.
    pub async fn spawn(&self) -> anyhow::Result<(JoinHandle<anyhow::Result<()>>, u16)> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", self.port))
            .await
            .context("failed to bind to gRPC port")?;

        // We do this to get the actual port if configured with `self.port=0`.
        let port = listener
            .local_addr()
            .expect("local address should exist for a tcp listener")
            .port();

        tracing::info!(
            server.timeout=%humantime::Duration::from(self.timeout),
            server.capacity=self.capacity,
            proof.kind = %self.kind,
            server.port = port,
            "proof server listening"
        );

        let status_service = status::StatusService::new(self.kind);
        let prover_service = ProverService::with_capacity(self.kind, self.capacity);
        let prover_service = ApiServer::new(prover_service);

        let reflection_service = tonic_reflection::server::Builder::configure()
            .register_file_descriptor_set(miden_node_proto_build::remote_prover_api_descriptor())
            .register_encoded_file_descriptor_set(tonic_health::pb::FILE_DESCRIPTOR_SET)
            .build_v1()
            .context("failed to build reflection service")?;

        // Create a gRPC health reporter.
        let (health_reporter, health_service) = tonic_health::server::health_reporter();

        // Mark the service as serving
        health_reporter.set_serving::<ApiServer<ProverService>>().await;

        let server = tonic::transport::Server::builder()
            .accept_http1(true)
            .layer(CatchPanicLayer::custom(catch_panic_layer_fn))
            .layer(TraceLayer::new_for_grpc().make_span_with(grpc_trace_fn))
            .layer(cors_for_grpc_web_layer())
            .layer(GrpcWebLayer::new())
            .timeout(self.timeout)
            .add_service(prover_service)
            .add_service(status_service)
            .add_service(health_service)
            .add_service(reflection_service)
            .serve_with_incoming(TcpListenerStream::new(listener));

        let server =
            tokio::spawn(async move { server.await.context("failed while serving proof server") });

        Ok((server, port))
    }
}

/// A bundle of gRPC services and a TCP listener, ready to be served.
pub struct RpcListener {
    pub api_service: ApiServer<service::ProverService>,
    pub status_service:
        crate::generated::worker_status_api_server::WorkerStatusApiServer<status::StatusService>,
    pub listener: TcpListener,
}

impl RpcListener {
    pub fn new(listener: TcpListener, kind: ProofKind) -> Self {
        let capacity = NonZeroUsize::new(1).unwrap();
        let prover_service = service::ProverService::with_capacity(kind, capacity);
        let api_service = ApiServer::new(prover_service);
        let status_service = status::StatusService::new(kind);
        Self { api_service, status_service, listener }
    }
}
