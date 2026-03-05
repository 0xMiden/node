use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use accept::AcceptHeaderLayer;
use anyhow::Context;
use miden_node_proto::generated::rpc::api_server;
use miden_node_proto_build::rpc_api_descriptor;
use miden_node_utils::cors::cors_for_grpc_web_layer;
use miden_node_utils::panic::{CatchPanicLayer, catch_panic_layer_fn};
use miden_node_utils::tracing::grpc::grpc_trace_fn;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::service::InterceptorLayer;
use tonic::transport::server::TcpConnectInfo;
use tonic_reflection::server;
use tonic_web::GrpcWebLayer;
use tower::limit::GlobalConcurrencyLimitLayer;
use tower_governor::GovernorError;
use tower_governor::key_extractor::KeyExtractor;
use tower_http::trace::TraceLayer;
use tracing::info;
use url::Url;

use crate::COMPONENT;
use crate::server::health::HealthCheckLayer;

mod accept;
mod api;
mod connect_info;
mod health;

#[derive(Clone, Copy, Debug)]
struct RpcPeerIpExtractor;

impl KeyExtractor for RpcPeerIpExtractor {
    type Key = IpAddr;

    fn extract<T>(&self, req: &http::Request<T>) -> Result<Self::Key, GovernorError> {
        req.extensions()
            .get::<TcpConnectInfo>()
            .and_then(TcpConnectInfo::remote_addr)
            .map(|addr| addr.ip())
            .ok_or(GovernorError::UnableToExtractKey)
    }
}

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
    /// Server-side timeout for an individual gRPC request.
    ///
    /// If the handler takes longer than this duration, the server cancels the call.
    pub grpc_request_timeout: Duration,
    /// Maximum duration of a connection before we drop it.
    pub grpc_max_connection_age: Duration,
    /// Number of connections to be served before the "API tokens" need to be replenished
    /// per IP address.
    pub grpc_burst_size: u64,
    /// Number of requests to unlock per second.
    pub grpc_replenish_per_sec: u64,
    /// Number of global concurrent connections.
    pub grpc_max_global_concurrent_connections: u64,
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

        // This is currently required for postman to work properly because
        // it doesn't support the new version yet.
        //
        // See: <https://github.com/postmanlabs/postman-app-support/issues/13120>.
        let reflection_service_alpha = server::Builder::configure()
            .register_file_descriptor_set(rpc_api_descriptor())
            .build_v1alpha()
            .context("failed to build reflection service")?;

        info!(target: COMPONENT, endpoint=?self.listener, store=%self.store_url, block_producer=?self.block_producer_url, "Server initialized");

        let rpc_version = env!("CARGO_PKG_VERSION");
        let rpc_version =
            semver::Version::parse(rpc_version).context("failed to parse crate version")?;

        let rate_limiter = {
            let config = tower_governor::governor::GovernorConfigBuilder::default()
                .key_extractor(RpcPeerIpExtractor)
                .per_second(self.grpc_replenish_per_sec)
                .burst_size(self.grpc_burst_size as u32)
                .use_headers()
                .finish()
                .context("config parameters are inconsistent, i.e. burst < per second")?;
            let limiter = Arc::clone(config.limiter());
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(60));
                loop {
                    interval.tick().await;
                    // avoid a DoS vector
                    limiter.retain_recent();
                }
            });
            tower_governor::GovernorLayer::new(config)
        };

        tonic::transport::Server::builder()
            .accept_http1(true)
            .max_connection_age(self.grpc_max_connection_age)
            .timeout(self.grpc_request_timeout)
            .layer(InterceptorLayer::new(connect_info::ConnectInfoInterceptor))
            .layer(CatchPanicLayer::custom(catch_panic_layer_fn))
            .layer(TraceLayer::new_for_grpc().make_span_with(grpc_trace_fn))
            .layer(HealthCheckLayer)
            // TODO uses a semaphore, we might want to move to a single atomic in relaxed ordering
            .layer(GlobalConcurrencyLimitLayer::new(self.grpc_max_global_concurrent_connections as usize))
            .layer(rate_limiter)
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
            .add_service(reflection_service_alpha)
            .serve_with_incoming(TcpListenerStream::new(self.listener))
            .await
            .context("failed to serve RPC API")
    }
}
