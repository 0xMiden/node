use std::sync::Arc;

use miden_protocol::block::{BlockNumber, BlockSigner, ProposedBlock};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::Signature;
use miden_protocol::errors::ProposedBlockError;
use miden_protocol::transaction::TransactionId;
use tracing::{Instrument, info_span};

use crate::server::ValidatedTransactions;

// BLOCK VALIDATION ERROR
// ================================================================================================

#[derive(thiserror::Error, Debug)]
pub enum BlockValidationError {
    #[error("transaction {0} in block {1} has not been validated")]
    TransactionNotValidated(TransactionId, BlockNumber),
    #[error("failed to build block")]
    BlockBuildingFailed(#[from] ProposedBlockError),
}

// BLOCK VALIDATION
// ================================================================================================

/// Validates a block by checking that all transactions in the proposed block have been processed by
/// the validator in the past.
///
/// Removes the validated transactions from the cache upon success.
pub async fn validate_block<S: BlockSigner>(
    proposed_block: ProposedBlock,
    signer: &S,
    validated_transactions: Arc<ValidatedTransactions>,
) -> Result<Signature, BlockValidationError> {
    // Check that all transactions in the proposed block have been validated
    let verify_span = info_span!("verify_transactions");
    for tx_header in proposed_block.transactions() {
        let tx_id = tx_header.id();
        // TODO: LruCache is a poor abstraction since it locks many times.
        if validated_transactions
            .get(&tx_id)
            .instrument(verify_span.clone())
            .await
            .is_none()
        {
            return Err(BlockValidationError::TransactionNotValidated(
                tx_id,
                proposed_block.block_num(),
            ));
        }
    }

    // Build the block header.
    let (header, _) = proposed_block.into_header_and_body()?;

    // Sign the header.
    let signature = info_span!("sign_block").in_scope(|| signer.sign(&header));

    Ok(signature)
}
