use std::fmt::Display;
use std::num::NonZeroUsize;
use std::sync::Arc;

use accept::AcceptHeaderLayer;
use anyhow::Context;
use miden_node_block_producer::{BlockProducerApi, RpcReadiness, RpcSync};
use miden_node_proto::clients::{
    NtxBuilderClient,
    RpcClient as SourceRpcClient,
    SequencerClient,
    ValidatorClient,
};
use miden_node_proto::server::{rpc_api, sequencer_api};
use miden_node_proto_build::rpc_api_descriptor;
use miden_node_store::state::{BlockWriter, ProofWriter, State};
use miden_node_utils::clap::GrpcOptions;
use miden_node_utils::cors::cors_for_grpc_web_layer;
use miden_node_utils::grpc;
use miden_node_utils::panic::{CatchPanicLayer, catch_panic_layer_fn};
use miden_node_utils::shutdown::CancellationToken;
use miden_node_utils::tasks::Tasks;
use miden_node_utils::tracing::grpc::grpc_trace_fn;
use rand::RngExt;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::metadata::AsciiMetadataValue;
use tonic_reflection::server;
use tonic_web::GrpcWebLayer;
use tower_http::classify::{GrpcCode, GrpcErrorsAsFailures, SharedClassifier};
use tower_http::trace::TraceLayer;
use tracing::info;

use crate::LOG_TARGET;
use crate::server::api::SequencerInternalService;
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
    pub state: Arc<State>,
    pub mode: RpcMode,
    pub ntx_builder: Option<NtxBuilderClient>,
    pub grpc_options: GrpcOptions,
    pub network_tx_auth: Option<AsciiMetadataValue>,
}

#[derive(Clone, Debug)]
/// Shared secret value expected in the fixed `x-miden-network-tx-auth` metadata header.
pub(crate) struct NetworkTxAuth(pub(crate) AsciiMetadataValue);

/// How the RPC is wired at startup: which submission path it runs and, in full-node mode, the
/// store write capabilities its sync loop consumes.
///
/// Deliberately not `Clone`: the full-node variant owns the store's single-writer capabilities,
/// which must not be duplicated. Per-request handlers never need those, so they read through
/// [`RpcBackend`] instead — the `Clone`-able subset [`Self::backend`] derives from this.
pub enum RpcMode {
    /// Sequencer RPC validates submissions locally, re-executes them through every validator, then
    /// forwards them to the block producer.
    ///
    /// Every validator must observe every transaction: a validator only signs blocks whose
    /// transactions it has previously validated, so a submission that misses a validator would
    /// later prevent that validator from signing the block containing it.
    Sequencer {
        block_producer: Box<BlockProducerApi>,
        validators: ValidatorClients,
    },
    /// Full-node RPC.
    ///
    /// By default it forwards submissions verbatim to the source RPC (the caller is responsible for
    /// configuring this client with any request metadata the source RPC requires).
    ///
    /// When the pre-authenticated submission clients are set, the full-node will, instead of
    /// forwarding, re-execute submissions through every validator and authenticate them against its
    /// store, then submit the authenticated result directly to the sequencer's internal API.
    FullNode {
        source_rpc: Box<SourceRpcClient>,
        readiness_threshold: u32,
        pre_auth: Option<PreAuthSubmission>,
        /// The store's block-write capability, handed to the sync loop.
        block_writer: BlockWriter,
        /// The store's proof-write capability, handed to the sync loop.
        proof_writer: ProofWriter,
    },
}

/// The clients handlers forward requests to — the per-request subset of [`RpcMode`], held by
/// [`RpcService`](api::RpcService) for the server's lifetime and read by every handler.
///
/// `Clone` because it is cloned once into `RpcService` and then read on every request; it never
/// carries the full-node's store write capabilities ([`RpcMode`] does), since no handler needs
/// them — those are consumed once by the sync loop at startup.
#[derive(Clone, Debug)]
pub(crate) enum RpcBackend {
    Sequencer {
        block_producer: Box<BlockProducerApi>,
        validators: ValidatorClients,
    },
    FullNode {
        source_rpc: Box<SourceRpcClient>,
        pre_auth: Option<PreAuthSubmission>,
    },
}

#[cfg(test)]
impl RpcBackend {
    /// Test-only: production code only ever builds a backend from an [`RpcMode`] via
    /// [`RpcMode::backend`]; these let handler-level tests construct one directly, without a store
    /// or write capabilities.
    pub(crate) fn sequencer(
        block_producer: BlockProducerApi,
        validators: ValidatorClients,
    ) -> Self {
        Self::Sequencer {
            block_producer: Box::new(block_producer),
            validators,
        }
    }

    pub(crate) fn full_node(
        source_rpc: SourceRpcClient,
        pre_auth: Option<PreAuthSubmission>,
    ) -> Self {
        Self::FullNode {
            source_rpc: Box::new(source_rpc),
            pre_auth,
        }
    }
}

/// A non-empty set of validator clients.
///
/// Every submission is re-executed through every validator, and state shared by the validator set
/// (such as the transaction encryption key) can be served by any single member, so an empty set is
/// rejected at construction.
#[derive(Clone, Debug)]
pub struct ValidatorClients(Vec<ValidatorClient>);

impl ValidatorClients {
    /// # Errors
    ///
    /// Fails if `validators` is empty.
    pub fn new(validators: Vec<ValidatorClient>) -> anyhow::Result<Self> {
        anyhow::ensure!(!validators.is_empty(), "at least one validator is required");
        Ok(Self(validators))
    }

    /// Returns a randomly chosen validator; use for state that any single validator can serve, so
    /// the load spreads across the set.
    pub(crate) fn random(&self) -> &ValidatorClient {
        let index = rand::rng().random_range(0..self.0.len());
        &self.0[index]
    }

    pub(crate) fn as_slice(&self) -> &[ValidatorClient] {
        &self.0
    }
}

/// Validator and sequencer clients for the full-node pre-authenticated submission path.
///
/// The two are only meaningful together: submissions are re-executed through every validator and
/// the authenticated result is submitted to the sequencer's internal API, so a full node is
/// configured with both or neither.
#[derive(Clone, Debug)]
pub struct PreAuthSubmission {
    validators: ValidatorClients,
    sequencer: Box<SequencerClient>,
}

impl PreAuthSubmission {
    /// # Errors
    ///
    /// Fails if `validators` is empty; every submission must be re-executed by the validator set.
    pub fn new(
        validators: Vec<ValidatorClient>,
        sequencer: SequencerClient,
    ) -> anyhow::Result<Self> {
        let validators = ValidatorClients::new(validators)
            .context("pre-authenticated submission requires at least one validator")?;
        Ok(Self {
            validators,
            sequencer: Box::new(sequencer),
        })
    }

    pub(crate) fn validators(&self) -> &ValidatorClients {
        &self.validators
    }

    pub(crate) fn sequencer(&self) -> &SequencerClient {
        &self.sequencer
    }
}

impl RpcMode {
    pub fn sequencer(block_producer: BlockProducerApi, validators: ValidatorClients) -> Self {
        Self::Sequencer {
            block_producer: Box::new(block_producer),
            validators,
        }
    }

    pub fn full_node(
        source_rpc: SourceRpcClient,
        readiness_threshold: u32,
        pre_auth: Option<PreAuthSubmission>,
        block_writer: BlockWriter,
        proof_writer: ProofWriter,
    ) -> Self {
        Self::FullNode {
            source_rpc: Box::new(source_rpc),
            readiness_threshold,
            pre_auth,
            block_writer,
            proof_writer,
        }
    }

    const fn as_str(&self) -> &'static str {
        match self {
            Self::Sequencer { .. } => "sequencer",
            Self::FullNode { .. } => "full",
        }
    }

    /// Returns the `Clone`-able per-request backend subset handed to
    /// [`RpcService`](api::RpcService).
    fn backend(&self) -> RpcBackend {
        match self {
            Self::Sequencer { block_producer, validators } => RpcBackend::Sequencer {
                block_producer: block_producer.clone(),
                validators: validators.clone(),
            },
            Self::FullNode { source_rpc, pre_auth, .. } => RpcBackend::FullNode {
                source_rpc: source_rpc.clone(),
                pre_auth: pre_auth.clone(),
            },
        }
    }
}

impl Rpc {
    /// Serves the RPC API.
    ///
    /// In full-node mode, also runs the block/proof sync loop concurrently. Either component
    /// failing causes both to stop.
    ///
    /// Note: Executes in place (i.e. not spawned) and will run indefinitely until
    ///       a fatal error is encountered.
    pub async fn serve(self, shutdown: CancellationToken) -> anyhow::Result<()> {
        let endpoint = self.listener.local_addr().context("failed to read RPC listen address")?;
        let mode = self.mode.as_str();
        let mut api = api::RpcService::new(
            self.state.clone(),
            self.mode.backend(),
            self.ntx_builder.clone(),
            NonZeroUsize::new(1_000_000).unwrap(),
            self.network_tx_auth.map(NetworkTxAuth),
        );

        let genesis = api
            .get_genesis_header_with_retry()
            .await
            .context("Fetching genesis header from store")?;

        api.set_genesis_commitment(genesis.commitment())?;

        let api_service = rpc_api::service(api);

        let mut tasks = Tasks::new();

        // Initialize health reporter and sync service based on the RPC mode.
        let (health_reporter, health_service) = tonic_health::server::health_reporter();
        match self.mode {
            RpcMode::Sequencer { .. } => {
                health_reporter
                    .set_service_status(
                        rpc_api::service_name(),
                        tonic_health::ServingStatus::Serving,
                    )
                    .await;
                let chain_tip = self.state.committed_tip();
                log_node_ready(mode, endpoint, chain_tip);
            },
            RpcMode::FullNode {
                source_rpc,
                readiness_threshold,
                block_writer,
                proof_writer,
                ..
            } => {
                Self::spawn_full_node_sync(
                    &self.state,
                    &mut tasks,
                    health_reporter,
                    mode,
                    endpoint,
                    shutdown.clone(),
                    *source_rpc,
                    readiness_threshold,
                    block_writer,
                    proof_writer,
                )
                .await;
            },
        }

        let reflection_service = server::Builder::configure()
            .register_file_descriptor_set(rpc_api_descriptor())
            .register_encoded_file_descriptor_set(tonic_health::pb::FILE_DESCRIPTOR_SET)
            .build_v1()
            .context("failed to build reflection service")?;

        let rpc_version = env!("CARGO_PKG_VERSION");
        let rpc_version =
            semver::Version::parse(rpc_version).context("failed to parse crate version")?;

        let rpc = tonic::transport::Server::builder()
            .accept_http1(true)
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
            // Note: must wrap the accept layer so grpc-web callers receive grpc-web-compatible
            // error responses instead of opaque transport failures.
            .layer(GrpcWebLayer::new())
            // Resolve the (load-balancer-aware) client IP once here so handlers can read it from
            // request extensions instead of re-deriving it from headers.
            .layer(grpc::ResolveClientIpLayer)
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
            .serve_with_incoming_shutdown(
                TcpListenerStream::new(self.listener),
                shutdown.clone().cancelled_owned(),
            );
        tasks.spawn("RPC server", async move { rpc.await.map_err(|e| anyhow::anyhow!(e)) });

        tasks.join_next_or_cancelled(shutdown).await
    }

    /// Marks the RPC `NotServing` until synchronized, then spawns the full-node sync loop.
    #[expect(
        clippy::too_many_arguments,
        reason = "assembles the full-node sync task from Rpc::serve's local state"
    )]
    async fn spawn_full_node_sync(
        state: &Arc<State>,
        tasks: &mut Tasks,
        health_reporter: tonic_health::server::HealthReporter,
        mode: &str,
        endpoint: impl Display,
        shutdown: CancellationToken,
        source_rpc: SourceRpcClient,
        readiness_threshold: u32,
        block_writer: BlockWriter,
        proof_writer: ProofWriter,
    ) {
        health_reporter
            .set_service_status(rpc_api::service_name(), tonic_health::ServingStatus::NotServing)
            .await;
        let readiness = RpcReadiness::new(health_reporter, readiness_threshold);
        tasks.spawn(
            "RPC sync",
            RpcSync {
                state: Arc::clone(state),
                block_writer,
                proof_writer,
                source_rpc,
                readiness,
            }
            .run(shutdown),
        );
        log_node_synchronizing(mode, endpoint, readiness_threshold);
    }
}

fn log_node_ready(mode: &str, endpoint: impl Display, chain_tip: impl Display) {
    info!(
        target: LOG_TARGET,
        {
            service.name = "miden-node",
            service.version = env!("CARGO_PKG_VERSION"),
            node.role = mode,
            rpc.listen = %endpoint,
            block.number = %chain_tip,
        },
        "Node ready",
    );
}

fn log_node_synchronizing(mode: &str, endpoint: impl Display, readiness_threshold: u32) {
    info!(
        target: LOG_TARGET,
        {
            service.name = "miden-node",
            service.version = env!("CARGO_PKG_VERSION"),
            node.role = mode,
            rpc.listen = %endpoint,
            sync.ready_threshold = readiness_threshold,
        },
        "Node started; synchronizing",
    );
}

// INTERNAL SEQUENCER
// ================================================================================================

/// The internal Sequencer server.
///
/// Serves the private `sequencer.Api` gRPC service, which accepts already-authenticated
/// transactions from full nodes and submits them directly to the mempool *without*
/// re-verification.
///
/// This must only ever be exposed on a private, network-isolated listener: callers can inject
/// transactions that the sequencer will not independently verify.
pub struct SequencerInternal {
    /// The listener the service binds to.
    pub listener: TcpListener,
    /// The in-process block producer API submissions are forwarded to.
    pub block_producer: BlockProducerApi,
    /// gRPC server options for internal services (timeouts).
    pub grpc_options: GrpcOptions,
}

impl SequencerInternal {
    /// Serves the internal sequencer API.
    ///
    /// Executes in place (i.e. not spawned) and will run indefinitely until a fatal error is
    /// encountered.
    pub async fn serve(self, shutdown: CancellationToken) -> anyhow::Result<()> {
        let endpoint = self
            .listener
            .local_addr()
            .context("failed to read internal sequencer listen address")?;
        info!(
            target: LOG_TARGET,
            { internal.listen = %endpoint },
            "Internal sequencer server ready",
        );

        let service = SequencerInternalService { block_producer: self.block_producer };

        // Note: deliberately no accept-header / auth layers; this is a private, trusted interface
        // and is expected to be network-isolated.
        tonic::transport::Server::builder()
            .layer(CatchPanicLayer::custom(catch_panic_layer_fn))
            .layer(TraceLayer::new_for_grpc().make_span_with(grpc_trace_fn))
            .timeout(self.grpc_options.request_timeout)
            .add_service(sequencer_api::service(service))
            .serve_with_incoming_shutdown(
                TcpListenerStream::new(self.listener),
                shutdown.cancelled_owned(),
            )
            .await
            .context("failed to serve internal sequencer API")
    }
}
