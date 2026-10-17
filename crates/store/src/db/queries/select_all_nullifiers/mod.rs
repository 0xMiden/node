//! Returns every stored nullifier.

use miden_node_db::sqlite::ReadTx;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::Nullifier;

use crate::db::NullifierInfo;
use crate::errors::DatabaseError;

const SQL: &str = include_str!("select_all_nullifiers.sql");

/// Returns every stored nullifier with the block at which it was created, ordered by nullifier.
pub(crate) fn select_all_nullifiers(tx: &ReadTx<'_>) -> Result<Vec<NullifierInfo>, DatabaseError> {
    Ok(tx.query(SQL, &[], |row| {
        Ok(NullifierInfo {
            nullifier: row.get::<Nullifier>(0)?,
            block_num: row.get::<BlockNumber>(1)?,
        })
    })?)
}
