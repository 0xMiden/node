use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use accept::AcceptHeaderLayer;
use anyhow::Context;
use miden_node_block_producer::BlockProducerApi;
use miden_node_proto::clients::{NtxBuilderClient, RpcClient as SourceRpcClient, ValidatorClient};
use miden_node_proto::generated::rpc::api_server;
use miden_node_proto_build::rpc_api_descriptor;
use miden_node_store::state::{Finality, State};
use miden_node_utils::clap::GrpcOptionsExternal;
use miden_node_utils::cors::cors_for_grpc_web_layer;
use miden_node_utils::grpc;
use miden_node_utils::panic::{CatchPanicLayer, catch_panic_layer_fn};
use miden_node_utils::tracing::grpc::grpc_trace_fn;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::Request;
use tonic::metadata::AsciiMetadataValue;
use tonic_reflection::server;
use tonic_web::GrpcWebLayer;
use tower_http::classify::{GrpcCode, GrpcErrorsAsFailures, SharedClassifier};
use tower_http::trace::TraceLayer;
use tracing::info;

use crate::COMPONENT;
use crate::server::health::HealthCheckLayer;

mod accept;
pub(crate) mod api;
mod health;

/// The RPC server component.
///
/// On startup, binds to the provided listener and starts serving the RPC API.
/// It uses the supplied store state and mode-specific submission handling.
pub struct Rpc {
    pub listener: TcpListener,
    pub store: Arc<State>,
    pub mode: RpcMode,
    pub ntx_builder: Option<NtxBuilderClient>,
    pub grpc_options: GrpcOptionsExternal,
    pub network_tx_auth: Option<AsciiMetadataValue>,
}

#[derive(Clone, Debug)]
/// Shared secret value expected in the fixed `x-miden-network-tx-auth` metadata header.
pub(crate) struct NetworkTxAuth(pub(crate) AsciiMetadataValue);

#[derive(Clone, Debug)]
pub enum RpcMode {
    /// Sequencer RPC validates submissions locally, re-executes them through the validator, then
    /// forwards them to the block producer.
    Sequencer {
        block_producer: Box<BlockProducerApi>,
        validator: Box<ValidatorClient>,
    },
    /// Full-node RPC forwards submissions to the source RPC.
    ///
    /// The caller is responsible for configuring this client with any request metadata the source
    /// RPC requires.
    FullNode {
        source_rpc: Box<SourceRpcClient>,
        readiness_threshold: u32,
    },
}

impl RpcMode {
    pub fn sequencer(block_producer: BlockProducerApi, validator: ValidatorClient) -> Self {
        Self::Sequencer {
            block_producer: Box::new(block_producer),
            validator: Box::new(validator),
        }
    }

    pub fn full_node(source_rpc: SourceRpcClient, readiness_threshold: u32) -> Self {
        Self::FullNode {
            source_rpc: Box::new(source_rpc),
            readiness_threshold,
        }
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
            self.network_tx_auth.map(NetworkTxAuth),
        );

        let genesis = api
            .get_genesis_header_with_retry()
            .await
            .context("Fetching genesis header from store")?;

        api.set_genesis_commitment(genesis.commitment())?;

        let api_service = api_server::ApiServer::new(api);

        info!(target: COMPONENT, endpoint=?self.listener, mode=?self.mode, "Server initialized");

        let (health_reporter, health_service) = tonic_health::server::health_reporter();
        match self.mode {
            RpcMode::Sequencer { .. } => {
                health_reporter
                    .set_serving::<api_server::ApiServer<api::RpcService>>()
                    .await;
            }
            RpcMode::FullNode {
                source_rpc,
                readiness_threshold,
            } => {
                health_reporter
                    .set_not_serving::<api_server::ApiServer<api::RpcService>>()
                    .await;
                let store = self.store.clone();
                tokio::spawn(async move {
                    run_readiness_monitor(health_reporter, *source_rpc, store, readiness_threshold)
                        .await;
                });
            }
        }

        let reflection_service = server::Builder::configure()
            .register_file_descriptor_set(rpc_api_descriptor())
            .register_encoded_file_descriptor_set(tonic_health::pb::FILE_DESCRIPTOR_SET)
            .build_v1()
            .context("failed to build reflection service")?;

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
            .add_service(health_service)
            // Enables gRPC reflection service.
            .add_service(reflection_service)
            .serve_with_incoming(TcpListenerStream::new(self.listener))
            .await
            .context("failed to serve RPC API")
    }
}

/// Polls the upstream RPC's status and updates the gRPC health service for the `rpc.Api` service.
///
/// Used in full-node mode where readiness depends on how close the local chain tip is to the
/// upstream sequencer's tip. Runs until the task is cancelled.
async fn run_readiness_monitor(
    reporter: tonic_health::server::HealthReporter,
    mut source_rpc: SourceRpcClient,
    store: Arc<State>,
    readiness_threshold: u32,
) {
    const POLL_INTERVAL: Duration = Duration::from_secs(5);

    loop {
        let is_ready = match source_rpc.status(Request::new(())).await {
            Ok(response) => {
                let upstream_tip = response
                    .into_inner()
                    .block_producer
                    .map_or(u32::MAX, |b| b.chain_tip);
                let local_tip = store.chain_tip(Finality::Committed).await.as_u32();
                upstream_tip.saturating_sub(local_tip) <= readiness_threshold
            }
            Err(_) => false,
        };

        if is_ready {
            reporter
                .set_serving::<api_server::ApiServer<api::RpcService>>()
                .await;
        } else {
            reporter
                .set_not_serving::<api_server::ApiServer<api::RpcService>>()
                .await;
        }

        tokio::time::sleep(POLL_INTERVAL).await;
    }
}
