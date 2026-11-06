use miden_node_db::DatabaseError;
use miden_node_db::sqlite::ReadTx;
use miden_node_utils::usdcx_p2id::UsdcxP2Id;

use super::read_deposit;
use crate::db::DatabaseIdentity;

/// Loads at most `limit` deposits not linked to an attempt, largest first, validating that the
/// funding account can consume each one.
pub fn select_largest_deposits(
    tx: &ReadTx<'_>,
    limit: i64,
    identity: DatabaseIdentity,
) -> Result<Vec<UsdcxP2Id>, DatabaseError> {
    tx.query(include_str!("select_largest_deposits.sql"), &[&limit], |row| {
        read_deposit(row, identity)
    })
}
