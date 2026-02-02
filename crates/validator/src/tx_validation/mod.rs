mod data_store;

pub use data_store::TransactionInputsDataStore;
use miden_protocol::MIN_PROOF_SECURITY_LEVEL;
use miden_protocol::transaction::{ProvenTransaction, TransactionHeader, TransactionInputs};
use miden_tx::auth::UnreachableAuth;
use miden_tx::{TransactionExecutor, TransactionExecutorError, TransactionVerifier};
use tracing::{Instrument, info_span};

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
    ProofVerificationFailed(#[from] miden_tx::TransactionVerifierError),
}

// TRANSACTION VALIDATION
// ================================================================================================

/// Validates a transaction by verifying its proof, executing it and comparing its header with the
/// provided proven transaction.
///
/// Returns the header of the executed transaction if successful.
pub async fn validate_transaction(
    proven_tx: ProvenTransaction,
    tx_inputs: TransactionInputs,
) -> Result<TransactionHeader, TransactionValidationError> {
    // First, verify the transaction proof
    info_span!("verify").in_scope(|| {
        let tx_verifier = TransactionVerifier::new(MIN_PROOF_SECURITY_LEVEL);
        tx_verifier.verify(&proven_tx)
    })?;

    // Create a DataStore from the transaction inputs.
    let data_store = TransactionInputsDataStore::new(tx_inputs.clone());

    // Execute the transaction.
    let (account, block_header, _, input_notes, tx_args) = tx_inputs.into_parts();
    let executor: TransactionExecutor<'_, '_, _, UnreachableAuth> =
        TransactionExecutor::new(&data_store);
    let executed_tx = executor
        .execute_transaction(account.id(), block_header.block_num(), input_notes, tx_args)
        .instrument(info_span!("execute"))
        .await?;

    // Validate that the executed transaction matches the submitted transaction.
    let executed_tx_header: TransactionHeader = (&executed_tx).into();
    let proven_tx_header: TransactionHeader = (&proven_tx).into();
    if executed_tx_header == proven_tx_header {
        Ok(executed_tx_header)
    } else {
        Err(TransactionValidationError::Mismatch {
            proven_tx_header: proven_tx_header.into(),
            executed_tx_header: executed_tx_header.into(),
        })
    }
}
