//! Returns every stored block header commitment, to rebuild the chain MMR at startup.

use miden_node_db::sqlite::ReadTx;
use miden_protocol::Word;

use crate::db::BlockHeaderCommitment;
use crate::errors::DatabaseError;

const SQL: &str = include_str!("select_all_block_header_commitments.sql");

/// Returns every stored block header commitment, ordered by block number ascending.
pub(crate) fn select_all_block_header_commitments(
    tx: &ReadTx<'_>,
) -> Result<Vec<BlockHeaderCommitment>, DatabaseError> {
    Ok(tx.query(SQL, &[], |row| row.get::<Word>(0).map(BlockHeaderCommitment))?)
}
