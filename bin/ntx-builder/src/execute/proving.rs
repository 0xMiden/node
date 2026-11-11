use miden_node_tracing::instrument;
use miden_node_utils::retry::Retryable;
use miden_protocol::transaction::{ProvenTransaction, TransactionInputs};
use miden_tx::TransactionProverError;

use super::{NtxContext, NtxError, NtxResult};
use crate::clients::log_transient_retry;

impl NtxContext {
    /// Delegates the transaction proof to the configured remote prover.
    ///
    /// Transient transport failures against the remote prover are retried in-place; intrinsic
    /// proving errors (witness rejected, malformed inputs) escape on the first attempt.
    #[instrument(name = "prove", err)]
    pub(super) async fn prove(
        &self,
        tx_inputs: &TransactionInputs,
    ) -> NtxResult<ProvenTransaction> {
        (|| async { self.prover.prove(tx_inputs).await })
            .retry(self.request_backoff())
            .when(|err| matches!(err, TransactionProverError::Other { .. }))
            .notify(|err, dur| {
                log_transient_retry("remote_prover.prove", err, dur);
            })
            .await
            .map_err(NtxError::Proving)
    }
}
