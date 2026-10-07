//! Returns a block header and the validator signatures that committed it.

use miden_node_db::sqlite::ReadTx;
use miden_protocol::block::{BlockHeader, BlockNumber, BlockSignatures};

use crate::errors::DatabaseError;

const SQL: &str = include_str!("select_block_header_and_signatures_by_block_num.sql");

/// Returns the block header at `block_num` and its validator signatures.
pub(crate) fn select_block_header_and_signatures_by_block_num(
    tx: &ReadTx<'_>,
    block_num: BlockNumber,
) -> Result<Option<(BlockHeader, BlockSignatures)>, DatabaseError> {
    // `block_num` is the primary key, so the statement returns zero or one row.
    let rows = tx.query(SQL, &[&block_num], |row| {
        Ok((row.get::<BlockHeader>(0)?, row.get::<BlockSignatures>(1)?))
    })?;

    Ok(rows.into_iter().next())
}
