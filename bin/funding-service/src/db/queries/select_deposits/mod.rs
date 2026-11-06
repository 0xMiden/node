use miden_node_db::DatabaseError;
use miden_node_db::sqlite::ReadTx;
use miden_node_utils::usdcx_p2id::UsdcxP2Id;

use super::read_deposit;
use crate::db::DatabaseIdentity;

/// Loads every stored deposit, largest first, validating that the funding account can consume each.
pub fn select_deposits(
    tx: &ReadTx<'_>,
    identity: DatabaseIdentity,
) -> Result<Vec<UsdcxP2Id>, DatabaseError> {
    tx.query(include_str!("select_deposits.sql"), &[], |row| read_deposit(row, identity))
}
