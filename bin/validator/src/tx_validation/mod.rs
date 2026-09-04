mod data_store;

pub use data_store::TransactionInputsDataStore;
use miden_node_tracing::spawn::{spawn_blocking_in_current_span, spawn_blocking_in_span};
use miden_node_tracing::{Instrument, info_span, miden_instrument};
use miden_protocol::MIN_PROOF_SECURITY_LEVEL;
use miden_protocol::errors::TransactionVerifierError;
use miden_protocol::transaction::{
    ProvenTransaction,
    TransactionHeader,
    TransactionInputs,
    TransactionVerifier,
};
use miden_tx::auth::UnreachableAuth;
use miden_tx::{TransactionExecutor, TransactionExecutorError};

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
    ProofVerificationFailed(#[from] TransactionVerifierError),
    #[error("transaction proof has an outstanding precompile obligation")]
    IncompleteProof,
}

// TRANSACTION VALIDATION
// ================================================================================================

/// Validates a transaction by verifying its proof, executing it and comparing its header with the
/// provided proven transaction.
///
#[miden_instrument(
    target = COMPONENT,
    err,
)]
pub async fn validate_transaction(
    proven_tx: ProvenTransaction,
    tx_inputs: TransactionInputs,
) -> Result<(), TransactionValidationError> {
    if !proven_tx.proof().is_complete() {
        return Err(TransactionValidationError::IncompleteProof);
    }

    // Proof verification is CPU-intensive; run it on a dedicated blocking thread.
    let proven_tx_clone = proven_tx.clone();
    let verification_outcome = spawn_blocking_in_span(
        move || TransactionVerifier::new(MIN_PROOF_SECURITY_LEVEL).verify(&proven_tx_clone),
        info_span!("verify"),
    )
    .await
    .unwrap_or_else(|e| std::panic::resume_unwind(e.into_panic()))?;
    if !verification_outcome.is_complete() {
        return Err(TransactionValidationError::IncompleteProof);
    }

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
        Ok(())
    } else {
        Err(TransactionValidationError::Mismatch {
            proven_tx_header: proven_tx_header.into(),
            executed_tx_header: executed_tx_header.into(),
        })
    }
}
