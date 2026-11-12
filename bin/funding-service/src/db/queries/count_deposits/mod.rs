use miden_node_db::DatabaseError;
use miden_node_db::sqlite::ReadTx;

/// Returns the number of stored deposits.
pub fn count_deposits(tx: &ReadTx<'_>) -> Result<i64, DatabaseError> {
    Ok(tx
        .query(include_str!("count_deposits.sql"), &[], |row| row.get(0))?
        .into_iter()
        .next()
        .unwrap_or_default())
}
