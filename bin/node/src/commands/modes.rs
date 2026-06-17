use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use miden_node_block_producer::Sequencer;
use miden_node_proto::clients::{
    Builder,
    NtxBuilderClient,
    RpcClient,
    TrustedClient,
    ValidatorClient,
};
use miden_node_rpc::{Rpc, RpcMode, Trusted, TrustedSubmission};
use miden_node_store::State;
use miden_node_utils::clap::GrpcOptionsInternal;
use miden_node_utils::tasks::Tasks;
use tokio::net::TcpListener;
use url::Url;

use super::block_producer::BlockProducerOptions;
use super::rpc::SyncOptions;
use super::runtime::{RuntimeConfig, RuntimeOptions};
use super::store::StoreOptions;

// RUNTIME MODES
// ================================================================================================

#[derive(clap::Args, Clone, Debug)]
pub struct SequencerCommand {
    #[command(flatten)]
    pub runtime: RuntimeOptions,

    #[command(flatten)]
    pub external_services: SequencerExternalServiceOptions,

    #[command(flatten)]
    pub block_producer: BlockProducerOptions,

    #[command(flatten)]
    pub store: StoreOptions,

    /// Socket address at which to serve the private trusted submission API.
    ///
    /// When unset the trusted submission service is not exposed. This interface accepts
    /// already-authenticated transactions from trusted full nodes *without* re-verification.
    #[arg(
        long = "trusted.listen",
        env = "MIDEN_NODE_TRUSTED_LISTEN",
        value_name = "LISTEN"
    )]
    pub trusted_listen: Option<SocketAddr>,
}

impl SequencerCommand {
    pub async fn handle(self) -> anyhow::Result<()> {
        let runtime = self.runtime.runtime_config(&self.store);
        self.block_producer.validate()?;
        let network_tx_auth = self.runtime.rpc.network_tx_auth()?;
        let state = load_state(&runtime).await?;
        let _disk_monitor = state.spawn_disk_monitor();

        let sequencer = Sequencer {
            store: Arc::clone(&state),
            validator_url: self.external_services.validator_url.clone(),
            batch_prover_url: self.block_producer.batch.prover_url,
            block_prover_url: self.block_producer.block_prover.url,
            batch_interval: self.block_producer.batch.interval,
            block_interval: self.block_producer.block.interval,
            max_txs_per_batch: self.block_producer.batch.max_txs,
            max_batches_per_block: self.block_producer.block.max_batches,
            max_concurrent_proofs: self.block_producer.block.max_concurrent_proofs,
            mempool_tx_capacity: self.block_producer.mempool.tx_capacity,
        }
        .spawn()
        .await
        .context("failed to spawn sequencer")?;
        let block_producer = sequencer.api();

        let rpc = Rpc {
            listener: bind_rpc(runtime.rpc_listen).await?,
            store: state,
            mode: RpcMode::sequencer(
                block_producer.clone(),
                self.external_services.validator_client()?,
            ),
            ntx_builder: Some(self.external_services.ntx_builder_client()?),
            grpc_options: runtime.external_grpc_options,
            network_tx_auth,
        };
        let mut tasks = Tasks::new();
        tasks.spawn("sequencer", sequencer.wait());
        tasks.spawn("RPC server", rpc.serve());
        if let Some(trusted_listen) = self.trusted_listen {
            let trusted = Trusted {
                listener: bind_rpc(trusted_listen).await?,
                block_producer,
                grpc_options: GrpcOptionsInternal::from(runtime.external_grpc_options),
            };
            tasks.spawn("trusted submission server", trusted.serve());
        }

        tasks.join_next_as_error().await
    }
}

#[derive(clap::Args, Clone, Debug)]
pub struct SequencerExternalServiceOptions {
    /// The validator service gRPC URL.
    #[arg(long = "validator.url", env = "MIDEN_NODE_VALIDATOR_URL", value_name = "URL")]
    pub validator_url: Url,

    /// The network transaction builder service gRPC URL.
    #[arg(long = "ntx-builder.url", env = "MIDEN_NODE_NTX_BUILDER_URL", value_name = "URL")]
    pub ntx_builder_url: Url,
}

impl SequencerExternalServiceOptions {
    fn validator_client(&self) -> anyhow::Result<ValidatorClient> {
        Ok(Builder::new(self.validator_url.clone())
            .with_tls()?
            .without_timeout()
            .without_metadata_version()
            .without_metadata_genesis()
            .with_otel_context_injection()
            .connect_lazy::<ValidatorClient>())
    }

    fn ntx_builder_client(&self) -> anyhow::Result<NtxBuilderClient> {
        Ok(Builder::new(self.ntx_builder_url.clone())
            .with_tls()?
            .without_timeout()
            .without_metadata_version()
            .without_metadata_genesis()
            .with_otel_context_injection()
            .connect_lazy::<NtxBuilderClient>())
    }
}

#[derive(clap::Args, Clone, Debug)]
pub struct FullNodeCommand {
    #[command(flatten)]
    pub runtime: RuntimeOptions,

    #[command(flatten)]
    pub sync: SyncOptions,

    #[command(flatten)]
    pub store: StoreOptions,

    #[command(flatten)]
    pub trusted: TrustedFullNodeOptions,
}

impl FullNodeCommand {
    pub async fn handle(self) -> anyhow::Result<()> {
        let runtime = self.runtime.runtime_config(&self.store);
        let source_rpc = self.sync.source_rpc_client()?;
        let trusted = self.trusted.trusted_submission()?;
        let network_tx_auth = self.runtime.rpc.network_tx_auth()?;
        let state = load_state(&runtime).await?;
        let _disk_monitor = state.spawn_disk_monitor();

        let rpc = Rpc {
            listener: bind_rpc(runtime.rpc_listen).await?,
            store: state,
            mode: RpcMode::full_node(source_rpc, self.sync.readiness_threshold, trusted),
            ntx_builder: None,
            grpc_options: runtime.external_grpc_options,
            network_tx_auth,
        };
        let mut tasks = Tasks::new();
        tasks.spawn("RPC server", rpc.serve());

        tasks.join_next_as_error().await
    }
}

/// Options that turn a full node into a *trusted* full node.
///
/// When both URLs are set the full node validates and authenticates submissions locally and
/// forwards the authenticated result to the sequencer's trusted submission API, rather than
/// forwarding the raw transaction upstream. Both must be provided together.
#[derive(clap::Args, Clone, Debug)]
pub struct TrustedFullNodeOptions {
    /// The validator service gRPC URL.
    #[arg(
        long = "validator.url",
        env = "MIDEN_NODE_VALIDATOR_URL",
        value_name = "URL",
        requires = "sequencer_url"
    )]
    pub validator_url: Option<Url>,

    /// The sequencer's private trusted submission gRPC URL.
    #[arg(
        long = "sequencer.url",
        env = "MIDEN_NODE_SEQUENCER_URL",
        value_name = "URL",
        requires = "validator_url"
    )]
    pub sequencer_url: Option<Url>,
}

impl TrustedFullNodeOptions {
    /// Builds the trusted submission clients, or `None` if this full node is not trusted.
    fn trusted_submission(&self) -> anyhow::Result<Option<TrustedSubmission>> {
        let (Some(validator_url), Some(sequencer_url)) = (&self.validator_url, &self.sequencer_url)
        else {
            return Ok(None);
        };

        let validator = Builder::new(validator_url.clone())
            .with_tls()?
            .with_timeout(Duration::from_secs(20))
            .without_metadata_version()
            .without_metadata_genesis()
            .with_otel_context_injection()
            .connect_lazy::<ValidatorClient>();

        let sequencer = Builder::new(sequencer_url.clone())
            .with_tls()?
            .with_timeout(Duration::from_secs(20))
            .without_metadata_version()
            .without_metadata_genesis()
            .with_otel_context_injection()
            .connect_lazy::<TrustedClient>();

        Ok(Some(TrustedSubmission {
            validator: Box::new(validator),
            sequencer: Box::new(sequencer),
        }))
    }
}

impl SyncOptions {
    fn source_rpc_client(&self) -> anyhow::Result<RpcClient> {
        Ok(Builder::new(self.block_source_url.clone())
            .with_tls()?
            .without_timeout()
            .without_metadata_version()
            .without_metadata_genesis()
            .with_otel_context_injection()
            .connect_lazy::<RpcClient>())
    }
}

async fn load_state(runtime: &RuntimeConfig) -> anyhow::Result<Arc<State>> {
    let state = State::load_with_database_options(
        &runtime.data_directory,
        runtime.storage_options.clone(),
        runtime.database_options,
    )
    .await
    .context("failed to load state")?;

    Ok(Arc::new(state))
}

async fn bind_rpc(listen: SocketAddr) -> anyhow::Result<TcpListener> {
    TcpListener::bind(listen)
        .await
        .with_context(|| format!("failed to bind RPC listener to {listen}"))
}
