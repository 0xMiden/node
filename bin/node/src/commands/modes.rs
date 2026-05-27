use miden_node_proto::clients::{Builder, NtxBuilderClient, RpcClient, ValidatorClient};
use url::Url;

use super::block_producer::BlockProducerOptions;
use super::rpc::SyncOptions;
use super::runtime::RuntimeOptions;
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
}

impl SequencerCommand {
    pub fn handle(self) -> anyhow::Result<()> {
        let runtime = self.runtime.runtime_config(&self.store);
        self.block_producer.validate()?;
        let validator = self.external_services.validator_client();
        let ntx_builder = self.external_services.ntx_builder_client();
        let _ = (
            runtime.rpc_listen,
            runtime.data_directory,
            validator,
            ntx_builder,
            self.block_producer.block_prover.url,
            runtime.database_options,
            runtime.internal_grpc_options,
            runtime.external_grpc_options,
            runtime.storage_options,
            self.block_producer.block.max_concurrent_proofs,
        );

        anyhow::bail!(
            "sequencer mode runtime composition is not implemented yet; this stage only defines \
             the CLI"
        )
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
    fn validator_client(&self) -> ValidatorClient {
        Builder::new(self.validator_url.clone())
            .without_tls()
            .without_timeout()
            .without_metadata_version()
            .without_metadata_genesis()
            .with_otel_context_injection()
            .connect_lazy::<ValidatorClient>()
    }

    fn ntx_builder_client(&self) -> NtxBuilderClient {
        Builder::new(self.ntx_builder_url.clone())
            .without_tls()
            .without_timeout()
            .without_metadata_version()
            .without_metadata_genesis()
            .with_otel_context_injection()
            .connect_lazy::<NtxBuilderClient>()
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
}

impl FullNodeCommand {
    pub fn handle(self) -> anyhow::Result<()> {
        let runtime = self.runtime.runtime_config(&self.store);
        let source_rpc = self.sync.source_rpc_client();
        let _ = (
            runtime.rpc_listen,
            runtime.data_directory,
            runtime.database_options,
            runtime.internal_grpc_options,
            runtime.external_grpc_options,
            runtime.storage_options,
            source_rpc,
        );

        anyhow::bail!(
            "full node mode block-stream sync is not implemented yet; this stage only defines the \
             CLI"
        )
    }
}

impl SyncOptions {
    fn source_rpc_client(&self) -> RpcClient {
        Builder::new(self.block_source_url.clone())
            .without_tls()
            .without_timeout()
            .without_metadata_version()
            .without_metadata_genesis()
            .with_otel_context_injection()
            .connect_lazy::<RpcClient>()
    }
}
