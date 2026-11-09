mod data_store;

#[cfg(test)]
mod tests;

pub use data_store::TransactionInputsDataStore;
use miden_node_tracing::spawn::{spawn_blocking_in_current_span, spawn_blocking_in_span};
use miden_node_tracing::{Instrument, info_span_v2, instrument_v2};
use miden_protocol::MIN_PROOF_SECURITY_LEVEL;
use miden_protocol::errors::TransactionVerifierError;
use miden_protocol::transaction::{
    ProvenTransaction,
    TransactionArgs,
    TransactionEffects,
    TransactionHeader,
    TransactionInputs,
    TransactionVerifier,
};
use miden_tx::auth::UnreachableAuth;
use miden_tx::{TransactionExecutor, TransactionExecutorError};

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
}

// TRANSACTION VALIDATION
// ================================================================================================

/// Validates a transaction by verifying its proof, executing it and comparing its header with the
/// provided proven transaction.
///
/// Returns the effects of the re-executed transaction. The effects hold the account state
/// commitments, the account patch, the input and output notes, the reference block and the
/// expiration block.
#[instrument_v2]
pub async fn validate_transaction(
    proven_tx: ProvenTransaction,
    tx_inputs: TransactionInputs,
) -> Result<TransactionEffects, TransactionValidationError> {
    // Verify the proof on a blocking thread. The verifier also checks deferred witnesses. Batch
    // proving settles the remaining precompile obligation.
    let proven_tx_clone = proven_tx.clone();
    let _verification_outcome = spawn_blocking_in_span(
        move || TransactionVerifier::new(MIN_PROOF_SECURITY_LEVEL).verify(&proven_tx_clone),
        info_span_v2!("verify"),
    )
    .await
    .unwrap_or_else(|e| std::panic::resume_unwind(e.into_panic()))?;

    // Create a DataStore from the transaction inputs.
    let data_store = TransactionInputsDataStore::new(tx_inputs.clone());

    // VM execution may not yield; run it on a dedicated blocking thread.
    let tx_args = replay_args(&tx_inputs);
    let (account, block_header, _, input_notes, _) = tx_inputs.into_parts();
    let execute_span = info_span_v2!("execute").or_current();
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
    //
    // FIXME: Also compare the reference block and expiration. TransactionHeader omits both.
    let executed_tx_header: TransactionHeader = (&executed_tx).into();
    let proven_tx_header: TransactionHeader = (&proven_tx).into();
    if executed_tx_header == proven_tx_header {
        Ok(TransactionEffects::from(&executed_tx))
    } else {
        Err(TransactionValidationError::Mismatch {
            proven_tx_header: proven_tx_header.into(),
            executed_tx_header: executed_tx_header.into(),
        })
    }
}

fn replay_args(inputs: &TransactionInputs) -> TransactionArgs {
    let mut args = inputs.tx_args().clone();
    for signature in inputs.signatures() {
        args.add_signature(signature.clone());
    }
    args
}
