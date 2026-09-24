use miden_node_tracing::spawn::spawn_blocking_in_current_span;
use miden_node_tracing::{miden_instrument, miden_span_record};
use miden_protocol::MIN_PROOF_SECURITY_LEVEL;
use miden_protocol::batch::{ProposedBatch, ProvenBatch};
use miden_tx_batch::{BatchExecutor, LocalBatchProver};

use crate::COMPONENT;
use crate::errors::BuildBatchError;

/// Proves batches locally without generating precompile proofs.
#[derive(Clone)]
pub(crate) struct BatchProver(LocalBatchProver);

impl BatchProver {
    pub(crate) fn new() -> Self {
        Self(LocalBatchProver::default().skip_precompile_proof_generation(true))
    }

    #[miden_instrument(target = COMPONENT, name = "batch_builder.prove_batch", err)]
    pub(crate) async fn prove(
        &self,
        proposed_batch: ProposedBatch,
    ) -> Result<ProvenBatch, BuildBatchError> {
        miden_span_record!(prover.kind = "local");
        let prover = self.0.clone();
        let proven_batch = spawn_blocking_in_current_span(move || {
            let executed_batch = BatchExecutor::new()
                .execute(proposed_batch)
                .map_err(BuildBatchError::ProveBatchError)?;
            prover.prove(executed_batch).map_err(BuildBatchError::ProveBatchError)
        })
        .await
        .map_err(BuildBatchError::JoinError)??;
        if proven_batch.proof_security_level() < MIN_PROOF_SECURITY_LEVEL {
            Err(BuildBatchError::SecurityLevelTooLow(
                proven_batch.proof_security_level(),
                MIN_PROOF_SECURITY_LEVEL,
            ))
        } else {
            Ok(proven_batch)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use miden_node_utils::testing::deferred_transaction_fixture;
    use miden_tx_batch::BatchVerifier;

    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn proves_batches_with_deferred_precompiles() -> anyhow::Result<()> {
        let fixture = deferred_transaction_fixture().await;
        assert!(fixture.transaction.proof().has_precompiles());
        let proposed = ProposedBatch::new(
            vec![Arc::new(fixture.transaction.clone())],
            fixture.inputs.block_header().clone(),
            fixture.inputs.blockchain().clone(),
            BTreeMap::new(),
            MIN_PROOF_SECURITY_LEVEL,
        )?;

        let proven = BatchProver::new().prove(proposed.clone()).await?;

        assert_eq!(proven.id(), proposed.id());
        assert_eq!(proven.account_updates(), proposed.account_updates());
        assert_eq!(proven.input_notes(), proposed.input_notes());
        assert_eq!(proven.output_notes(), proposed.output_notes());
        BatchVerifier::new(MIN_PROOF_SECURITY_LEVEL).verify(&proven)?;
        Ok(())
    }
}
