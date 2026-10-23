use miden_node_db::DatabaseError;
use miden_node_db::sqlite::ReadTx;

use super::select_attempt_requests;
use crate::db::TransactionAttempt;

/// Reads the transaction awaiting confirmation and its requests, oldest first.
pub fn select_attempt(tx: &ReadTx<'_>) -> Result<Option<TransactionAttempt>, DatabaseError> {
    let attempt = tx
        .query(include_str!("select_attempt.sql"), &[], |row| {
            Ok(TransactionAttempt {
                transaction_id: row.get(0)?,
                reference_block: row.get(1)?,
                expiration_block: row.get(2)?,
                deposit_nullifier: row.get(3)?,
                note_ids: Vec::new(),
            })
        })?
        .into_iter()
        .next();
    attempt
        .map(|mut attempt| {
            attempt.note_ids = select_attempt_requests(tx, attempt.transaction_id)?;
            Ok(attempt)
        })
        .transpose()
}
