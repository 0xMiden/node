//! Inserts a block header and the signatures that committed it.

use miden_node_db::sqlite::WriteTx;
use miden_node_tracing::instrument_v2;
use miden_protocol::block::{BlockHeader, BlockSignatures};

use crate::db::BlockHeaderCommitment;
use crate::errors::DatabaseError;

const SQL: &str = include_str!("insert_block_header.sql");

/// Inserts a [`BlockHeader`] and its [`BlockSignatures`].
///
/// The header's commitment is stored alongside it so the chain MMR can be rebuilt without
/// deserializing every header.
///
/// # Returns
///
/// The number of affected rows.
#[instrument_v2(err)]
pub(crate) fn insert_block_header(
    tx: &WriteTx<'_>,
    block_header: &BlockHeader,
    signatures: &BlockSignatures,
) -> Result<usize, DatabaseError> {
    let commitment = BlockHeaderCommitment::new(block_header).word();

    Ok(tx.execute(SQL, &[&block_header.block_num(), block_header, signatures, &commitment])?)
}
