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
        let _ = (
            runtime.rpc_listen,
            runtime.data_directory,
            self.external_services.validator_url,
            self.external_services.ntx_builder_url,
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
    #[arg(
        long = "validator.url",
        env = "MIDEN_NODE_VALIDATOR_URL",
        value_name = "URL",
        display_order = 4
    )]
    pub validator_url: Url,

    /// The network transaction builder service gRPC URL.
    #[arg(
        long = "ntx-builder.url",
        env = "MIDEN_NODE_NTX_BUILDER_URL",
        value_name = "URL",
        display_order = 5
    )]
    pub ntx_builder_url: Url,
}

#[derive(clap::Args, Clone, Debug)]
pub struct RpcCommand {
    #[command(flatten)]
    pub runtime: RuntimeOptions,

    #[command(flatten)]
    pub sync: SyncOptions,

    #[command(flatten)]
    pub store: StoreOptions,
}

impl RpcCommand {
    pub fn handle(self) -> anyhow::Result<()> {
        let runtime = self.runtime.runtime_config(&self.store);
        let _ = (
            runtime.rpc_listen,
            runtime.data_directory,
            runtime.database_options,
            runtime.internal_grpc_options,
            runtime.external_grpc_options,
            runtime.storage_options,
            self.sync.block_source_url,
        );

        anyhow::bail!(
            "rpc mode block-stream sync is not implemented yet; this stage only defines the CLI"
        )
    }
}
