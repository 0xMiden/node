mod data_store;
mod validated_tx;

pub use data_store::TransactionInputsDataStore;
use miden_node_utils::spawn::{spawn_blocking_in_current_span, spawn_blocking_in_span};
use miden_protocol::MIN_PROOF_SECURITY_LEVEL;
use miden_protocol::transaction::{
    ProvenTransaction,
    TransactionHeader,
    TransactionInputs,
    TransactionVerifier,
};
use miden_tx::auth::UnreachableAuth;
use miden_tx::{TransactionExecutor, TransactionExecutorError};
use tracing::{Instrument, info_span, instrument};
pub use validated_tx::ValidatedTransaction;

use crate::COMPONENT;

// TRANSACTION VALIDATION ERROR
// ================================================================================================

#[derive(thiserror::Error, Debug)]
pub enum TransactionValidationError {
    #[error("failed to re-executed the transaction")]
    ExecutionError(#[from] TransactionExecutorError),
    #[error("re-executed transaction did not match the provided proven transaction")]
    Mismatch {
        proven_tx_header: Box<TransactionHeader>,
        executed_tx_header: Box<TransactionHeader>,
    },
    #[error("transaction proof verification failed")]
    ProofVerificationFailed(#[from] miden_protocol::errors::TransactionVerifierError),
}

// TRANSACTION VALIDATION
// ================================================================================================

/// Validates a transaction by verifying its proof, executing it and comparing its header with the
/// provided proven transaction.
///
/// Returns the header of the executed transaction if successful.
#[instrument(target = COMPONENT, skip_all, err)]
pub async fn validate_transaction(
    proven_tx: ProvenTransaction,
    tx_inputs: TransactionInputs,
) -> Result<ValidatedTransaction, TransactionValidationError> {
    // Proof verification is CPU-intensive; run it on a dedicated blocking thread.
    let proven_tx_clone = proven_tx.clone();
    spawn_blocking_in_span(
        move || TransactionVerifier::new(MIN_PROOF_SECURITY_LEVEL).verify(&proven_tx_clone),
        info_span!("verify"),
    )
    .await
    .unwrap_or_else(|e| std::panic::resume_unwind(e.into_panic()))?;

    // Create a DataStore from the transaction inputs.
    let data_store = TransactionInputsDataStore::new(tx_inputs.clone());

    // VM execution may not yield; run it on a dedicated blocking thread.
    let (account, block_header, _, input_notes, tx_args) = tx_inputs.into_parts();
    let execute_span = info_span!("execute").or_current();
    let executed_tx = spawn_blocking_in_current_span(move || {
        let executor: TransactionExecutor<'_, '_, _, UnreachableAuth> =
            TransactionExecutor::new(&data_store);
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("failed to build tokio runtime")
            .block_on(
                executor
                    .execute_transaction(
                        account.id(),
                        block_header.block_num(),
                        input_notes,
                        tx_args,
                    )
                    .instrument(execute_span),
            )
    })
    .await
    .unwrap_or_else(|e| std::panic::resume_unwind(e.into_panic()))?;

    // Validate that the executed transaction matches the submitted transaction.
    let executed_tx_header: TransactionHeader = (&executed_tx).into();
    let proven_tx_header: TransactionHeader = (&proven_tx).into();
    if executed_tx_header == proven_tx_header {
        Ok(ValidatedTransaction::new(executed_tx))
    } else {
        Err(TransactionValidationError::Mismatch {
            proven_tx_header: proven_tx_header.into(),
            executed_tx_header: executed_tx_header.into(),
        })
    }
}
