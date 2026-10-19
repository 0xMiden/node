//! Restores proving inputs for committed, unproven blocks and blocks recovered from validators.

use anyhow::Context;
use miden_node_proto::BlockProofRequest;
use miden_node_store::{BlockWriter, State};
use miden_node_tracing::warn;
use miden_protocol::block::{BlockNumber, SignedBlock};

use super::RecoveredBlock;
use crate::LOG_TARGET;

/// Loads a local proving request and checks that it reconstructs the supplied block.
///
/// Missing, corrupt, or mismatched requests return `None` so recovery can replace them. Other
/// filesystem errors propagate to avoid hiding inaccessible storage.
pub(super) async fn load_valid_local_inputs(
    state: &State,
    block: &SignedBlock,
) -> anyhow::Result<Option<BlockProofRequest>> {
    let height = block.header().block_num();
    let Some(bytes) = state.load_proving_inputs(height).await? else {
        return Ok(None);
    };
    let decoded = (|| -> anyhow::Result<BlockProofRequest> {
        let request = miden_node_persistence::decode::<BlockProofRequest>(&bytes)?;
        request.validate_against(block)?;
        Ok(request)
    })();
    match decoded {
        Ok(request) => Ok(Some(request)),
        Err(error) => {
            warn!(error, target: LOG_TARGET, "Local proving inputs require recovery", block.number = height);
            Ok(None)
        },
    }
}

/// Finds the first block that needs recovery of its proving inputs or the block itself.
///
/// Missing or invalid inputs above the validators' recovery target cause an error before recovery
/// writes begin, since validator backups cannot repair them.
pub(super) async fn recovery_start(
    state: &State,
    target: BlockNumber,
) -> anyhow::Result<Option<BlockNumber>> {
    let committed = state.committed_tip();
    let mut first_gap = None;
    for raw in u64::from(state.proven_tip().as_u32()) + 1..=u64::from(committed.as_u32()) {
        let height = BlockNumber::from(u32::try_from(raw)?);
        let bytes = state
            .load_block(height)
            .await?
            .context("committed block missing from storage")?;
        let block = miden_node_persistence::decode::<SignedBlock>(&bytes)?;
        if load_valid_local_inputs(state, &block).await?.is_none() {
            anyhow::ensure!(
                height <= target,
                "missing proving inputs for block {height} exceed validator recovery tip {target}"
            );
            first_gap.get_or_insert(height);
        }
    }
    if let Some(first) = first_gap {
        return Ok(Some(first));
    }
    Ok((committed < target).then(|| committed.child()))
}

/// Repairs an existing block's inputs or saves inputs before committing a new block.
///
/// Recovery preserves valid local input files and rejects blocks that differ from the local chain.
/// Supplied proving requests must reconstruct the recovered block even when local inputs are valid.
pub(super) async fn apply_recovered(
    state: &State,
    writer: &mut BlockWriter,
    recovered: RecoveredBlock,
) -> anyhow::Result<()> {
    let height = recovered.block.header().block_num();
    let is_existing = height <= state.committed_tip();
    let local = if is_existing {
        let bytes = state.load_block(height).await?.context("local committed block is missing")?;
        Some(miden_node_persistence::decode::<SignedBlock>(&bytes)?)
    } else {
        None
    };
    if let Some(local) = &local {
        anyhow::ensure!(
            local.header() == recovered.block.header() && local.body() == recovered.block.body(),
            "validator block {height} diverges from the local committed block"
        );
    }
    if let Some(request) = &recovered.proving_inputs {
        request.validate_against(&recovered.block)?;
    }
    let local_inputs = if let Some(local) = &local {
        load_valid_local_inputs(state, local).await?
    } else {
        None
    };
    if local_inputs.is_none() {
        let request = recovered.proving_inputs.context(format!(
            "no proving inputs available for block {height}; restore original sequencer inputs or sync an existing proof before promotion",
        ))?;
        writer.save_proving_inputs(height, &request).await?;
    }
    if !is_existing {
        writer.apply_block(recovered.block, recovered.protocol_config).await?;
    }
    Ok(())
}
