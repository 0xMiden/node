//! Reconciles proving requests with the locally committed unproven suffix.

use anyhow::Context;
use miden_node_proto::BlockProofRequest;
use miden_node_store::{BlockWriter, State};
use miden_node_tracing::warn;
use miden_protocol::block::{BlockNumber, SignedBlock};

use super::RecoveredBlock;
use crate::LOG_TARGET;

/// Loads a usable request, treating missing or corrupt files as recoverable gaps.
///
/// Filesystem errors other than absence remain fatal so recovery cannot hide inaccessible storage.
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

/// Finds the earliest missing request or block and rejects gaps beyond validator coverage.
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
/// Existing valid input files are preserved exactly; validator material cannot replace a divergent
/// local block or overwrite a valid file before its binding has been checked.
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
