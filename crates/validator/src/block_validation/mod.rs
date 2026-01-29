use std::collections::HashMap;

use miden_node_store::{DatabaseError, Db};
use miden_protocol::block::{BlockNumber, BlockSigner, ProposedBlock};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::Signature;
use miden_protocol::errors::ProposedBlockError;
use miden_protocol::transaction::{TransactionHeader, TransactionId};
use tracing::info_span;

use crate::db::select_validated_transactions;

// BLOCK VALIDATION ERROR
// ================================================================================================

#[derive(thiserror::Error, Debug)]
pub enum BlockValidationError {
    #[error("transaction {0} in block {1} has not been validated")]
    TransactionNotValidated(TransactionId, BlockNumber),
    #[error(
        "the proposed transaction {proposed_tx} does not match the validated transaction {validated_tx}"
    )]
    TransactionMismatch {
        proposed_tx: TransactionId,
        validated_tx: TransactionId,
    },
    #[error("failed to build block")]
    BlockBuildingFailed(#[from] ProposedBlockError),
    #[error("failed to select transactions")]
    DatabaseError(#[from] DatabaseError),
    #[error("internal error: {0}")]
    Other(String),
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
    db: &Db,
) -> Result<Signature, BlockValidationError> {
    // Create a map of transactions from the proposed block.
    let proposed_transactions = proposed_block
        .transactions()
        .map(|header| (header.id(), header.clone()))
        .collect::<HashMap<TransactionId, TransactionHeader>>();

    // Retrieve all validated transactions pertaining to the proposed block.
    let proposed_tx_ids =
        proposed_block.transactions().map(TransactionHeader::id).collect::<Vec<_>>();
    let query_tx_ids = proposed_tx_ids.clone();
    let validated_transactions = db
        .transact("select_transactions", move |conn| {
            select_validated_transactions(conn, &query_tx_ids)
        })
        .await?;

    // Check that every transaction from the proposed block has been validated.
    for proposed_tx_id in proposed_tx_ids {
        let Some(validated_tx) = validated_transactions.get(&proposed_tx_id) else {
            return Err(BlockValidationError::TransactionNotValidated(
                proposed_tx_id,
                proposed_block.block_num(),
            ));
        };
        // Check that the proposed and validated transactions are equal.
        let proposed_tx =
            proposed_transactions.get(&proposed_tx_id).ok_or(BlockValidationError::Other(
                "proposed transactions mapped incorrectly from proposed block".into(),
            ))?;
        if validated_tx != proposed_tx {
            return Err(BlockValidationError::TransactionMismatch {
                proposed_tx: proposed_tx.id(),
                validated_tx: validated_tx.id(),
            });
        }
    }

    // Build the block header.
    let (header, _) = proposed_block.into_header_and_body()?;

    // Sign the header.
    let signature = info_span!("sign_block").in_scope(|| signer.sign(&header));

    Ok(signature)
}
