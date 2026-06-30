use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use miden_node_proto::clients::{Builder, ValidatorClient};
use miden_node_proto::generated::validator::BlockSubscriptionRequest;
use miden_node_store::State;
use miden_node_store::state::Finality;
use miden_protocol::block::{BlockNumber, SignedBlock};
use miden_protocol::utils::serde::Deserializable;
use tokio_stream::StreamExt;
use tracing::info;
use url::Url;

use super::ENV_DATA_DIRECTORY;
use super::store::StoreOptions;

// RECOVER
// ================================================================================================

#[derive(clap::Args, Clone, Debug)]
pub struct RecoverCommand {
    /// Directory containing the node's local data storage.
    #[arg(long, env = ENV_DATA_DIRECTORY, value_name = "DIR")]
    data_directory: PathBuf,

    /// The validator service gRPC URL to recover blocks from.
    #[arg(long = "validator.url", env = "MIDEN_NODE_VALIDATOR_URL", value_name = "URL")]
    validator_url: Url,

    #[command(flatten)]
    store: StoreOptions,
}

impl RecoverCommand {
    pub async fn handle(self) -> anyhow::Result<()> {
        let state = self.load_state().await?;
        let validator = self.validator_client()?;
        recover_from_validator(&state, validator).await
    }

    async fn load_state(&self) -> anyhow::Result<Arc<State>> {
        let state = State::load_with_database_options(
            &self.data_directory,
            self.store.storage.clone().into(),
            self.store.sqlite.database_options(),
        )
        .await
        .context("failed to load state")?;

        Ok(Arc::new(state))
    }

    fn validator_client(&self) -> anyhow::Result<ValidatorClient> {
        Ok(Builder::new(self.validator_url.clone())
            .with_tls()?
            .with_timeout(Duration::from_secs(5))
            .without_metadata_version()
            .without_metadata_genesis()
            .with_otel_context_injection()
            .connect_lazy::<ValidatorClient>())
    }
}

/// Streams blocks from the validator into the local store until the chain tip is reached.
async fn recover_from_validator(
    state: &Arc<State>,
    mut validator: ValidatorClient,
) -> anyhow::Result<()> {
    // Capture the validator's chain tip as the recovery target. The validator's block stream
    // follows live blocks indefinitely, so without a fixed target we could never tell when to stop.
    // The sequencer must be shut down during recovery, so this tip does not advance.
    let validator_tip = BlockNumber::from(
        validator
            .status(())
            .await
            .context("failed to query validator status")?
            .into_inner()
            .chain_tip,
    );

    let local_tip = state.chain_tip(Finality::Committed).await;
    if local_tip >= validator_tip {
        info!(
            local.tip = local_tip.as_u32(),
            validator.tip = validator_tip.as_u32(),
            "Local chain is already at the validator's chain tip; nothing to recover",
        );
        return Ok(());
    }

    let block_from = local_tip.child().as_u32();
    info!(
        block_from,
        validator.tip = validator_tip.as_u32(),
        "Recovering blocks from validator",
    );

    let mut stream = validator
        .block_subscription(BlockSubscriptionRequest { block_from })
        .await
        .context("failed to open validator block subscription")?
        .into_inner();

    while let Some(result) = stream.next().await {
        let event = result.context("validator block stream returned an error")?;
        let block = SignedBlock::read_from_bytes(&event.block)
            .context("failed to deserialize block from validator")?;
        let block_num = block.header().block_num();
        state.apply_block(block).await.context("failed to apply recovered block")?;
        info!(block.number = block_num.as_u32(), "Applied recovered block");

        // Stop once we reach the tip captured at the start of recovery.
        if block_num >= validator_tip {
            break;
        }
    }

    // The stream can end before reaching the tip if the validator restarts or drops the connection.
    let final_tip = state.chain_tip(Finality::Committed).await;
    anyhow::ensure!(
        final_tip >= validator_tip,
        "validator block stream ended at block {} before reaching the chain tip {}",
        final_tip.as_u32(),
        validator_tip.as_u32(),
    );

    info!(chain_tip = final_tip.as_u32(), "Block recovery complete");
    Ok(())
}
