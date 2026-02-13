use std::time::Duration;

use clap::Parser;
use miden_node_utils::cors::cors_for_grpc_web_layer;
use miden_node_utils::panic::{CatchPanicLayer, catch_panic_layer_fn};
use miden_node_utils::tracing::grpc::grpc_trace_fn;
use miden_remote_prover::COMPONENT;
use miden_remote_prover::api::{ProofType, RpcListener};
use miden_remote_prover::generated::api_server::ApiServer;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic_health::server::health_reporter;
use tonic_web::GrpcWebLayer;
use tower_http::trace::TraceLayer;
use tracing::{info, instrument};

/// Starts a worker.
#[derive(Debug, Parser)]
pub struct StartWorker {
    /// Use localhost (127.0.0.1) instead of 0.0.0.0
    #[arg(long, env = "MRP_WORKER_LOCALHOST")]
    pub localhost: bool,
    /// The port of the worker
    #[arg(long, default_value = "50051", env = "MRP_WORKER_PORT")]
    pub port: u16,
    /// The type of proof that the worker will be handling
    #[arg(long, env = "MRP_WORKER_PROOF_TYPE")]
    pub proof_type: ProofType,
    /// Maximum time allowed for a request to complete. Once exceeded, the request is
    /// aborted.
    #[arg(long, default_value = "60s", env = "MRP_TIMEOUT", value_parser = humantime::parse_duration)]
    pub(crate) timeout: Duration,
}

impl StartWorker {
    /// Starts a worker.
    ///
    /// This method receives the port from the CLI and starts a worker on that port.
    /// The host will be 127.0.0.1 if --localhost is specified, otherwise 0.0.0.0.
    /// In case that the port is not provided, it will default to `50051`.
    ///
    /// The worker includes a health reporter that will mark the service as serving, following the
    /// [gRPC health checking protocol](
    /// https://github.com/grpc/grpc-proto/blob/master/grpc/health/v1/health.proto).
    #[instrument(target = COMPONENT, name = "worker.execute")]
    pub async fn execute(&self) -> anyhow::Result<()> {
        let host = if self.localhost { "127.0.0.1" } else { "0.0.0.0" };
        let worker_addr = format!("{}:{}", host, self.port);
        let rpc = RpcListener::new(TcpListener::bind(&worker_addr).await?, self.proof_type);

        let server_addr = rpc.listener.local_addr()?;
        info!(target: COMPONENT,
            endpoint = %server_addr,
            proof_type = ?self.proof_type,
            host = %host,
            port = %self.port,
            "Worker server initialized and listening"
        );

        // Create a health reporter
        let (health_reporter, health_service) = health_reporter();

        // Mark the service as serving
        health_reporter.set_serving::<ApiServer<RpcListener>>().await;

        tonic::transport::Server::builder()
            .accept_http1(true)
            .layer(CatchPanicLayer::custom(catch_panic_layer_fn))
            .layer(TraceLayer::new_for_grpc().make_span_with(grpc_trace_fn))
            .layer(cors_for_grpc_web_layer())
            .layer(GrpcWebLayer::new())
            .timeout(self.timeout)
            .add_service(rpc.api_service)
            .add_service(rpc.status_service)
            .add_service(health_service)
            .serve_with_incoming(TcpListenerStream::new(rpc.listener))
            .await?;

        Ok(())
    }
}
