use super::block_producer::BlockProducerOptions;
use super::rpc::SyncOptions;
use super::runtime::RuntimeOptions;

// RUNTIME MODES
// ================================================================================================

#[derive(clap::Args, Clone, Debug)]
pub struct SequencerCommand {
    #[command(flatten)]
    pub runtime: RuntimeOptions,

    #[command(flatten)]
    pub block_producer: BlockProducerOptions,
}

impl SequencerCommand {
    pub fn handle(self) -> anyhow::Result<()> {
        let runtime = self.runtime.runtime_config();
        self.block_producer.validate()?;
        let _ = (
            runtime.rpc_listen,
            runtime.data_directory,
            runtime.validator_url,
            runtime.ntx_builder_url,
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
pub struct RpcCommand {
    #[command(flatten)]
    pub runtime: RuntimeOptions,

    #[command(flatten)]
    pub sync: SyncOptions,
}

impl RpcCommand {
    pub fn handle(self) -> anyhow::Result<()> {
        let runtime = self.runtime.runtime_config();
        let _ = (
            runtime.rpc_listen,
            runtime.data_directory,
            runtime.validator_url,
            runtime.ntx_builder_url,
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
