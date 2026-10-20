//! Finds which of a set of transactions have not been validated yet.

use std::collections::BTreeSet;

use miden_node_db::DatabaseError;
use miden_node_db::sqlite::{InList, ReadTx};
use miden_protocol::transaction::TransactionId;

const SQL: &str = include_str!("find_unvalidated_transactions.sql");

/// Scans the database for transaction ids that do not exist.
///
/// If the resulting vector is empty, all supplied transaction ids have been validated in the past.
pub fn find_unvalidated_transactions(
    tx: &ReadTx<'_>,
    tx_ids: &[TransactionId],
) -> Result<Vec<TransactionId>, DatabaseError> {
    let ids = InList::from_values(tx_ids);

    let validated = tx
        .query(SQL, &[&ids], |row| row.get::<TransactionId>(0))?
        .into_iter()
        .collect::<BTreeSet<_>>();

    Ok(tx_ids.iter().filter(|tx_id| !validated.contains(tx_id)).copied().collect())
}
