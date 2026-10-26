use miden_node_db::DatabaseError;
use miden_node_db::sqlite::WriteTx;

use crate::db::TransactionAttempt;

/// Records a transaction awaiting confirmation.
pub fn insert_attempt(tx: &WriteTx<'_>, attempt: &TransactionAttempt) -> Result<(), DatabaseError> {
    tx.execute(
        include_str!("insert_attempt.sql"),
        &[
            &attempt.transaction_id,
            &attempt.reference_block,
            &attempt.expiration_block,
            &attempt.deposit_nullifier,
        ],
    )?;
    Ok(())
}
