use accept::AcceptHeaderLayer;
use anyhow::Context;
use miden_node_proto::generated::rpc::api_server;
use miden_node_proto_build::rpc_api_descriptor;
use miden_node_tracing::info;
use miden_node_utils::clap::GrpcOptionsExternal;
use miden_node_utils::cors::cors_for_grpc_web_layer;
use miden_node_utils::grpc;
use miden_node_utils::panic::{CatchPanicLayer, catch_panic_layer_fn};
use miden_node_utils::tracing::grpc::grpc_trace_fn;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic_reflection::server;
use tonic_web::GrpcWebLayer;
use tower_http::classify::{GrpcCode, GrpcErrorsAsFailures, SharedClassifier};
use tower_http::trace::TraceLayer;
use url::Url;

use crate::COMPONENT;
use crate::server::health::HealthCheckLayer;

mod accept;
mod api;
mod health;

/// The RPC server component.
///
/// On startup, binds to the provided listener and starts serving the RPC API.
/// It connects lazily to the store, validator and block producer components as needed.
/// Requests will fail if the components are not available.
pub struct Rpc {
    pub listener: TcpListener,
    pub store_url: Url,
    pub block_producer_url: Option<Url>,
    pub validator_url: Url,
    pub ntx_builder_url: Option<Url>,
    pub grpc_options: GrpcOptionsExternal,
}

impl Rpc {
    /// Serves the RPC API.
    ///
    /// Note: Executes in place (i.e. not spawned) and will run indefinitely until
    ///       a fatal error is encountered.
    pub async fn serve(self) -> anyhow::Result<()> {
        let mut api = api::RpcService::new(
            self.store_url.clone(),
            self.block_producer_url.clone(),
            self.validator_url,
            self.ntx_builder_url.clone(),
        );

        let genesis = api
            .get_genesis_header_with_retry()
            .await
            .context("Fetching genesis header from store")?;

        api.set_genesis_commitment(genesis.commitment())?;

        let api_service = api_server::ApiServer::new(api);
        let reflection_service = server::Builder::configure()
            .register_file_descriptor_set(rpc_api_descriptor())
            .build_v1()
            .context("failed to build reflection service")?;

        info!(target: COMPONENT, endpoint=?self.listener, store=%self.store_url, block_producer=?self.block_producer_url, "Server initialized");

        let rpc_version = env!("CARGO_PKG_VERSION");
        let rpc_version =
            semver::Version::parse(rpc_version).context("failed to parse crate version")?;

        tonic::transport::Server::builder()
            .accept_http1(true)
            .max_connection_age(self.grpc_options.max_connection_age)
            .timeout(self.grpc_options.request_timeout)
            .layer(CatchPanicLayer::custom(catch_panic_layer_fn))
            .layer(grpc::connect_info_layer())
            .layer(
                TraceLayer::new(SharedClassifier::new(
                    GrpcErrorsAsFailures::new()
                        .with_success(GrpcCode::InvalidArgument)
                        .with_success(GrpcCode::NotFound)
                        .with_success(GrpcCode::ResourceExhausted)
                        .with_success(GrpcCode::Unimplemented)
                        .with_success(GrpcCode::Unknown),
                ))
                .make_span_with(grpc_trace_fn),
            )
            .layer(HealthCheckLayer)
            .layer(grpc::rate_limit_concurrent_connections(self.grpc_options))
            .layer(grpc::rate_limit_per_ip(self.grpc_options)?)
            // Note: must come before the accept layer, as otherwise accept rejections
            // do _not_ get CORS headers applied, masking the accept error in
            // web-clients (which would experience CORS rejection).
            .layer(cors_for_grpc_web_layer())
            .layer(
                AcceptHeaderLayer::new(&rpc_version, genesis.commitment())
                    .with_genesis_enforced_method("SubmitProvenTransaction")
                    .with_genesis_enforced_method("SubmitProvenBatch"),
            )
            // Enables gRPC-web support.
            .layer(GrpcWebLayer::new())
            .add_service(api_service)
            // Enables gRPC reflection service.
            .add_service(reflection_service)
            .serve_with_incoming(TcpListenerStream::new(self.listener))
            .await
            .context("failed to serve RPC API")
    }
}
