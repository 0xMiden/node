use miden_protocol::block::{BlockSigner, ProposedBlock};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::Signature;
use miden_protocol::errors::ProposedBlockError;
use miden_protocol::transaction::TransactionHeader;
use tracing::info_span;

use crate::db::{Database, DatabaseError};

// BLOCK VALIDATION ERROR
// ================================================================================================

#[derive(thiserror::Error, Debug)]
pub enum BlockValidationError {
    #[error("failed to build block")]
    BlockBuildingFailed(#[from] ProposedBlockError),
    #[error("failed to select transactions")]
    DatabaseError(#[from] DatabaseError),
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
    db: &Database,
) -> Result<Signature, BlockValidationError> {
    // Retrieve all validated transactions pertaining to the proposed block.
    let proposed_tx_ids =
        proposed_block.transactions().map(TransactionHeader::id).collect::<Vec<_>>();
    // TODO(currentpr): If we don't need to retrieve the data at all we can change this.
    let _validated_transactions = db.get(&proposed_tx_ids)?;

    // Build the block header.
    let (header, _) = proposed_block.into_header_and_body()?;

    // Sign the header.
    let signature = info_span!("sign_block").in_scope(|| signer.sign(&header));

    Ok(signature)
}
