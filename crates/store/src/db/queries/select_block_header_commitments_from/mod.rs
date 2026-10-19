//! Returns the block header commitments from a given block onwards, to top up a restored chain MMR
//! at startup.

use miden_node_db::sqlite::ReadTx;
use miden_protocol::Word;
use miden_protocol::block::BlockNumber;

use crate::db::BlockHeaderCommitment;
use crate::errors::DatabaseError;

const SQL: &str = include_str!("select_block_header_commitments_from.sql");

/// Returns the block header commitments starting at `from` (inclusive), ordered by block number
/// ascending.
pub(crate) fn select_block_header_commitments_from(
    tx: &ReadTx<'_>,
    from: BlockNumber,
) -> Result<Vec<BlockHeaderCommitment>, DatabaseError> {
    Ok(tx.query(SQL, &[&from], |row| row.get::<Word>(0).map(BlockHeaderCommitment))?)
}
