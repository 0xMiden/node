use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use miden_node_block_producer::{DEFAULT_VALIDATOR_TIMEOUT, Sequencer};
use miden_node_proto::clients::{
    Builder,
    NtxBuilderClient,
    RemoteProverClient,
    RpcClient,
    SequencerClient,
    ValidatorClient,
    WantsConnection,
};
use miden_node_rpc::{PreAuthSubmission, Rpc, RpcMode, SequencerInternal, ValidatorClients};
use miden_node_store::{BlockWriter, ProofWriter, State, WriterTask};
use miden_node_tracing::info;
use miden_node_utils::clap::duration_to_human_readable_string;
use miden_node_utils::formatting::format_endpoint;
use miden_node_utils::shutdown::CancellationToken;
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

    /// Socket address at which to serve the internal sequencer API.
    #[arg(
        long = "internal.listen",
        env = "MIDEN_NODE_SEQUENCER_INTERNAL_LISTEN",
        value_name = "LISTEN"
    )]
    pub internal: Option<SocketAddr>,
}

impl SequencerCommand {
    pub async fn handle(self, shutdown: CancellationToken) -> anyhow::Result<()> {
        self.log_starting();
        let runtime = self.runtime.runtime_config(&self.store);
        self.block_producer.validate()?;
        let network_tx_auth = self.runtime.rpc.network_tx_auth()?;
        let (validator_clients, validator_monitors) =
            self.external_services.validator_clients_and_monitors()?;
        let (ntx_builder_client, ntx_builder_monitor) =
            self.external_services.ntx_builder_client_and_monitor()?;
        let batch_prover_monitor =
            remote_prover_monitor(self.block_producer.batch.prover_url.as_ref())?;
        let block_prover_monitor =
            remote_prover_monitor(self.block_producer.block_prover.url.as_ref())?;
        let (state, block_writer, proof_writer, writer_task) =
            load_state(&runtime, shutdown.clone()).await?;
        let _disk_monitor = state.spawn_disk_monitor(shutdown.clone());

        let sequencer = Sequencer {
            state: Arc::clone(&state),
            block_writer,
            proof_writer,
            validator_urls: self.external_services.validator_urls.clone(),
            validator_timeout: self.external_services.validator_timeout,
            batch_prover_url: self.block_producer.batch.prover_url,
            block_prover_url: self.block_producer.block_prover.url,
            batch_interval: self.block_producer.batch.interval,
            block_interval: self.block_producer.block.interval,
            max_txs_per_batch: self.block_producer.batch.max_txs,
            max_batches_per_block: self.block_producer.block.max_batches,
            max_concurrent_proofs: self.block_producer.block.max_concurrent_proofs,
            mempool_tx_capacity: self.block_producer.mempool.tx_capacity,
            batch_workers: self.block_producer.batch.workers,
            builder_account_id: self.block_producer.builder.account_id,
        }
        .spawn(shutdown.clone())
        .context("failed to spawn sequencer")?;
        let block_producer = sequencer.api();

        let rpc = Rpc {
            listener: bind_rpc(runtime.rpc_listen).await?,
            state: Arc::clone(&state),
            mode: RpcMode::sequencer(block_producer.clone(), validator_clients),
            ntx_builder: Some(ntx_builder_client),
            grpc_options: runtime.grpc_options,
            network_tx_auth,
        };
        let mut tasks = Tasks::new();
        tasks.spawn("sequencer", sequencer.wait());
        tasks.spawn("RPC server", rpc.serve(shutdown.clone()));
        tasks.spawn("store block writer", join_store_writer(writer_task));
        for (index, validator_monitor) in validator_monitors.into_iter().enumerate() {
            tasks.spawn_infallible(
                format!("validator {index} connection monitor"),
                validator_monitor.monitor::<ValidatorClient>("validator", shutdown.clone()),
            );
        }
        tasks.spawn_infallible(
            "ntx-builder connection monitor",
            ntx_builder_monitor.monitor::<NtxBuilderClient>("ntx-builder", shutdown.clone()),
        );
        if let Some(batch_prover_monitor) = batch_prover_monitor {
            tasks.spawn_infallible(
                "batch prover connection monitor",
                batch_prover_monitor
                    .monitor::<RemoteProverClient>("batch-prover", shutdown.clone()),
            );
        }
        if let Some(block_prover_monitor) = block_prover_monitor {
            tasks.spawn_infallible(
                "block prover connection monitor",
                block_prover_monitor
                    .monitor::<RemoteProverClient>("block-prover", shutdown.clone()),
            );
        }
        if let Some(internal_listen) = self.internal {
            let sequencer_internal = SequencerInternal {
                listener: bind_rpc(internal_listen).await?,
                state,
                block_producer,
                grpc_options: runtime.grpc_options,
            };
            tasks.spawn("sequencer internal server", sequencer_internal.serve(shutdown.clone()));
        }

        tasks.join_next_or_cancelled(shutdown).await
    }

    fn log_starting(&self) {
        info!(
            target: crate::LOG_TARGET,
            "Starting node",
            service.name = "miden-node",
            service.version = env!("CARGO_PKG_VERSION"),
            node.role = "sequencer",
            rpc.listen = self.runtime.rpc.listen.to_string(),
            internal.listen = self.internal.map_or_else(
                || "disabled".to_owned(),
                |address| address.to_string(),
            ),
            data.directory = self.runtime.data_directory.as_path(),
            validator.endpoints = self
                .external_services
                .validator_urls
                .iter()
                .map(format_endpoint)
                .collect::<Vec<_>>()
                .join(","),
            ntx_builder.endpoint = format_endpoint(&self.external_services.ntx_builder_url),
            block.interval =
                humantime::Duration::from(self.block_producer.block.interval).to_string(),
            batch.interval =
                humantime::Duration::from(self.block_producer.batch.interval).to_string(),
            db.sqlite.connection_pool_size = self.store.sqlite.connection_pool_size.get()
        );
    }
}

#[derive(clap::Args, Clone, Debug)]
pub struct SequencerExternalServiceOptions {
    /// The validator service gRPC URLs.
    ///
    /// Repeat the flag once per validator (`--validator.url <URL> --validator.url <URL>`); the
    /// environment variable takes a comma-separated list. Transactions are submitted to, and
    /// blocks are signed by, every validator.
    #[arg(
        long = "validator.url",
        env = "MIDEN_NODE_VALIDATOR_URL",
        value_name = "URL",
        value_delimiter = ',',
        required = true
    )]
    pub validator_urls: Vec<Url>,

    /// Request timeout for calls to the validator service.
    ///
    /// Bounds the sequencer's `sign_block` call so a dropped validator connection fails fast and
    /// retries, rather than stalling block production until the OS-level TCP timeout.
    #[arg(
        long = "validator.timeout",
        env = "MIDEN_NODE_VALIDATOR_TIMEOUT",
        default_value = duration_to_human_readable_string(DEFAULT_VALIDATOR_TIMEOUT),
        value_parser = humantime::parse_duration,
        value_name = "DURATION"
    )]
    pub validator_timeout: Duration,

    /// The network transaction builder service gRPC URL.
    #[arg(long = "ntx-builder.url", env = "MIDEN_NODE_NTX_BUILDER_URL", value_name = "URL")]
    pub ntx_builder_url: Url,
}

impl SequencerExternalServiceOptions {
    fn validator_clients_and_monitors(
        &self,
    ) -> anyhow::Result<(ValidatorClients, Vec<Builder<WantsConnection>>)> {
        let builders = self
            .validator_urls
            .iter()
            .map(|url| {
                Ok(Builder::new(url.clone())
                    .with_tls()?
                    .with_timeout(self.validator_timeout)
                    .without_metadata_version()
                    .without_metadata_genesis()
                    .with_otel_context_injection())
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let clients =
            builders.iter().cloned().map(Builder::connect_lazy::<ValidatorClient>).collect();
        let clients = ValidatorClients::new(clients)?;
        Ok((clients, builders))
    }

    fn ntx_builder_client_and_monitor(
        &self,
    ) -> anyhow::Result<(NtxBuilderClient, Builder<WantsConnection>)> {
        let builder = Builder::new(self.ntx_builder_url.clone())
            .with_tls()?
            .without_timeout()
            .without_metadata_version()
            .without_metadata_genesis()
            .with_otel_context_injection();
        let client = builder.clone().connect_lazy::<NtxBuilderClient>();
        Ok((client, builder))
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

    /// The validator service gRPC URLs.
    ///
    /// Repeat the flag once per validator (`--validator.url <URL> --validator.url <URL>`); the
    /// environment variable takes a comma-separated list. Transactions are submitted to every
    /// validator.
    #[arg(
        long = "validator.url",
        env = "MIDEN_NODE_VALIDATOR_URL",
        value_name = "URL",
        value_delimiter = ',',
        requires = "sequencer_url"
    )]
    pub validator_urls: Vec<Url>,

    /// The sequencer's internal service gRPC URL.
    #[arg(
        long = "sequencer.internal.url",
        env = "MIDEN_NODE_SEQUENCER_INTERNAL_URL",
        value_name = "URL",
        requires = "validator_urls"
    )]
    pub sequencer_url: Option<Url>,
}

struct PreAuthComponents {
    submission: Option<PreAuthSubmission>,
    validator_monitors: Vec<Builder<WantsConnection>>,
    sequencer_monitor: Option<Builder<WantsConnection>>,
}

impl FullNodeCommand {
    pub async fn handle(self, shutdown: CancellationToken) -> anyhow::Result<()> {
        self.log_starting();
        let runtime = self.runtime.runtime_config(&self.store);
        let source_rpc = self.sync.source_rpc_client()?;
        let PreAuthComponents {
            submission: pre_auth,
            validator_monitors,
            sequencer_monitor,
        } = self.pre_auth_components()?;
        let network_tx_auth = self.runtime.rpc.network_tx_auth()?;
        let (state, block_writer, proof_writer, writer_task) =
            load_state(&runtime, shutdown.clone()).await?;
        let _disk_monitor = state.spawn_disk_monitor(shutdown.clone());

        let rpc = Rpc {
            listener: bind_rpc(runtime.rpc_listen).await?,
            state,
            mode: RpcMode::full_node(
                source_rpc,
                self.sync.readiness_threshold,
                pre_auth,
                block_writer,
                proof_writer,
            ),
            ntx_builder: None,
            grpc_options: runtime.grpc_options,
            network_tx_auth,
        };
        let mut tasks = Tasks::new();
        tasks.spawn("RPC server", rpc.serve(shutdown.clone()));
        tasks.spawn("store block writer", join_store_writer(writer_task));
        for (index, validator_monitor) in validator_monitors.into_iter().enumerate() {
            tasks.spawn_infallible(
                format!("validator {index} connection monitor"),
                validator_monitor.monitor::<ValidatorClient>("validator", shutdown.clone()),
            );
        }
        if let Some(sequencer_monitor) = sequencer_monitor {
            tasks.spawn_infallible(
                "sequencer connection monitor",
                sequencer_monitor.monitor::<SequencerClient>("sequencer", shutdown.clone()),
            );
        }

        tasks.join_next_or_cancelled(shutdown).await
    }

    fn pre_auth_components(&self) -> anyhow::Result<PreAuthComponents> {
        // Clap enforces that the sequencer URL and at least one validator URL come together.
        let Some(sequencer_url) = self.sequencer_url.as_ref() else {
            return Ok(PreAuthComponents {
                submission: None,
                validator_monitors: Vec::new(),
                sequencer_monitor: None,
            });
        };
        let sequencer_builder = Builder::new(sequencer_url.clone())
            .with_tls()
            .expect("TLS is enabled")
            .with_timeout(Duration::from_secs(5))
            .without_metadata_version()
            .without_metadata_genesis()
            .with_otel_context_injection();
        let sequencer = sequencer_builder.clone().connect_lazy::<SequencerClient>();
        let validator_builders = self
            .validator_urls
            .iter()
            .map(|url| {
                Builder::new(url.clone())
                    .with_tls()
                    .expect("TLS is enabled")
                    .with_timeout(Duration::from_secs(5))
                    .without_metadata_version()
                    .without_metadata_genesis()
                    .with_otel_context_injection()
            })
            .collect::<Vec<_>>();
        let validators = validator_builders
            .iter()
            .cloned()
            .map(Builder::connect_lazy::<ValidatorClient>)
            .collect();
        let pre_auth = PreAuthSubmission::new(validators, sequencer)?;
        Ok(PreAuthComponents {
            submission: Some(pre_auth),
            validator_monitors: validator_builders,
            sequencer_monitor: Some(sequencer_builder),
        })
    }

    fn log_starting(&self) {
        info!(
            target: crate::LOG_TARGET,
            "Starting node",
            service.name = "miden-node",
            service.version = env!("CARGO_PKG_VERSION"),
            node.role = "full",
            rpc.listen = self.runtime.rpc.listen.to_string(),
            data.directory = self.runtime.data_directory.as_path(),
            sync.block_source.endpoint = format_endpoint(&self.sync.block_source_url),
            sync.ready_threshold = self.sync.readiness_threshold,
            validator.endpoints = if self.validator_urls.is_empty() {
                "disabled".to_owned()
            } else {
                self.validator_urls.iter().map(format_endpoint).collect::<Vec<_>>().join(",")
            },
            sequencer.endpoint = self.sequencer_url.as_ref().map_or_else(
                || "disabled".to_owned(),
                format_endpoint,
            ),
            db.sqlite.connection_pool_size = self.store.sqlite.connection_pool_size.get()
        );
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

async fn load_state(
    runtime: &RuntimeConfig,
    shutdown: CancellationToken,
) -> anyhow::Result<(Arc<State>, BlockWriter, ProofWriter, WriterTask)> {
    let loaded = State::load_with_database_options(
        &runtime.data_directory,
        runtime.storage_options.clone(),
        runtime.database_options,
    )
    .await
    .context("failed to load state")?;

    Ok(loaded.start(shutdown))
}

/// Supervises the store's write worker task.
///
/// On shutdown the task-drain loop waits for the writer to finish any in-flight block write and
/// close its storage; an early exit or panic surfaces through the task set like any other task
/// failure.
async fn join_store_writer(writer_task: WriterTask) -> anyhow::Result<()> {
    writer_task.await.map_err(anyhow::Error::from)
}

async fn bind_rpc(listen: SocketAddr) -> anyhow::Result<TcpListener> {
    TcpListener::bind(listen)
        .await
        .with_context(|| format!("failed to bind RPC listener to {listen}"))
}

fn remote_prover_monitor(
    endpoint: Option<&Url>,
) -> anyhow::Result<Option<Builder<WantsConnection>>> {
    endpoint
        .map(|endpoint| {
            Ok(Builder::new(endpoint.clone())
                .with_tls()?
                .without_timeout()
                .without_metadata_version()
                .without_metadata_genesis()
                .without_auth_header()
                .with_otel_context_injection())
        })
        .transpose()
}
