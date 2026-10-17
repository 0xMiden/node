//! Row mapping shared by the `block_headers` queries.

use miden_node_db::DatabaseError;
use miden_node_db::sqlite::Row;
use miden_protocol::Word;
use miden_protocol::block::BlockHeader;

use crate::db::BlockHeaderCommitment;

/// Maps a `SELECT block_header, commitment` row to its [`BlockHeader`].
///
/// Debug builds also read the stored commitment and assert that it matches the header.
pub(super) fn block_header_from_row(row: &Row<'_>) -> Result<BlockHeader, DatabaseError> {
    let block_header = row.get::<BlockHeader>(0)?;
    debug_assert_eq!(
        BlockHeaderCommitment::new(&block_header),
        BlockHeaderCommitment(row.get::<Word>(1)?),
        "stored block header commitment does not match the stored header",
    );
    Ok(block_header)
}
