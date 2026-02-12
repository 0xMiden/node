use miden_node_store::{DatabaseError, Db};
use miden_protocol::block::{BlockSigner, ProposedBlock};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::Signature;
use miden_protocol::errors::ProposedBlockError;
use miden_protocol::transaction::{TransactionHeader, TransactionId};
use tracing::info_span;

use crate::db::find_unvalidated_transactions;

// BLOCK VALIDATION ERROR
// ================================================================================================

#[derive(thiserror::Error, Debug)]
pub enum BlockValidationError {
    #[error("block contains unvalidated transactions {0:?}")]
    UnvalidatedTransactions(Vec<TransactionId>),
    #[error("failed to build block")]
    BlockBuildingFailed(#[source] ProposedBlockError),
    #[error("failed to select transactions")]
    DatabaseError(#[source] DatabaseError),
}

// BLOCK VALIDATION
// ================================================================================================

/// Validates a block by checking that all transactions in the proposed block have been processed by
/// the validator in the past.
pub async fn validate_block<S: BlockSigner>(
    proposed_block: ProposedBlock,
    signer: &S,
    db: &Db,
) -> Result<Signature, BlockValidationError> {
    // Search for any proposed transactions that have not previously been validated.
    let proposed_tx_ids =
        proposed_block.transactions().map(TransactionHeader::id).collect::<Vec<_>>();
    let unvalidated_txs = db
        .transact("find_unvalidated_transactions", move |conn| {
            find_unvalidated_transactions(conn, &proposed_tx_ids)
        })
        .await
        .map_err(BlockValidationError::DatabaseError)?;

    // All proposed transactions must have been validated.
    if !unvalidated_txs.is_empty() {
        return Err(BlockValidationError::UnvalidatedTransactions(unvalidated_txs));
    }

    // Build the block header.
    let (header, _) = proposed_block
        .into_header_and_body()
        .map_err(BlockValidationError::BlockBuildingFailed)?;

    // Sign the header.
    let signature = info_span!("sign_block").in_scope(|| signer.sign(&header));

    Ok(signature)
}
