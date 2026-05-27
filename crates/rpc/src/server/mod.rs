use std::num::NonZeroUsize;

use accept::AcceptHeaderLayer;
use anyhow::Context;
use miden_node_proto::clients::{
    BlockProducerClient,
    NtxBuilderClient,
    RpcClient as SourceRpcClient,
    StoreRpcClient,
    ValidatorClient,
};
use miden_node_proto::generated::rpc::api_server;
use miden_node_proto_build::rpc_api_descriptor;
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
use tracing::info;

use crate::COMPONENT;
use crate::server::health::HealthCheckLayer;

mod accept;
mod api;
mod health;

/// The RPC server component.
///
/// On startup, binds to the provided listener and starts serving the RPC API.
/// It uses the supplied clients for store access and mode-specific submission handling.
/// Requests will fail if the supplied clients cannot reach their components.
pub struct Rpc {
    pub listener: TcpListener,
    pub store: StoreRpcClient,
    pub mode: RpcMode,
    pub ntx_builder: Option<NtxBuilderClient>,
    pub grpc_options: GrpcOptionsExternal,
}

#[derive(Clone, Debug)]
pub enum RpcMode {
    /// Sequencer RPC validates submissions locally, re-executes them through the validator, then
    /// forwards them to the block producer.
    Sequencer {
        block_producer: Box<BlockProducerClient>,
        validator: Box<ValidatorClient>,
    },
    /// Full-node RPC forwards submissions to the source RPC.
    ///
    /// The caller is responsible for configuring this client with any request metadata the source
    /// RPC requires.
    FullNode { source_rpc: Box<SourceRpcClient> },
}

impl RpcMode {
    pub fn sequencer(block_producer: BlockProducerClient, validator: ValidatorClient) -> Self {
        Self::Sequencer {
            block_producer: Box::new(block_producer),
            validator: Box::new(validator),
        }
    }

    pub fn full_node(source_rpc: SourceRpcClient) -> Self {
        Self::FullNode { source_rpc: Box::new(source_rpc) }
    }
}

impl Rpc {
    /// Serves the RPC API.
    ///
    /// Note: Executes in place (i.e. not spawned) and will run indefinitely until
    ///       a fatal error is encountered.
    pub async fn serve(self) -> anyhow::Result<()> {
        let mut api = api::RpcService::new(
            self.store.clone(),
            self.mode.clone(),
            self.ntx_builder.clone(),
            NonZeroUsize::new(1_000_000).unwrap(),
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

        info!(target: COMPONENT, endpoint=?self.listener, mode=?self.mode, "Server initialized");

        let rpc_version = env!("CARGO_PKG_VERSION");
        let rpc_version =
            semver::Version::parse(rpc_version).context("failed to parse crate version")?;

        tonic::transport::Server::builder()
            .accept_http1(true)
            .max_connection_age(self.grpc_options.max_connection_age)
            .timeout(self.grpc_options.request_timeout)
            .layer(CatchPanicLayer::custom(catch_panic_layer_fn))
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
            .layer(cors_for_grpc_web_layer())
            // Note: must wrap the accept/rate-limit layers so grpc-web callers receive
            // grpc-web-compatible error responses instead of opaque transport failures.
            .layer(GrpcWebLayer::new())
            .layer(grpc::rate_limit_concurrent_connections(self.grpc_options))
            .layer(grpc::rate_limit_per_ip(self.grpc_options)?)
            // Note: must come after the CORS layer, as otherwise accept rejections do _not_ get
            // CORS headers applied, masking the accept error in web-clients (which would experience
            // CORS rejection).
            .layer(
                AcceptHeaderLayer::new(&rpc_version, genesis.commitment())
                    .with_genesis_enforced_method("SubmitProvenTx")
                    .with_genesis_enforced_method("SubmitProvenTxBatch"),
            )
            .add_service(api_service)
            // Enables gRPC reflection service.
            .add_service(reflection_service)
            .serve_with_incoming(TcpListenerStream::new(self.listener))
            .await
            .context("failed to serve RPC API")
    }
}
