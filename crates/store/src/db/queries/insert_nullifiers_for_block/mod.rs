//! Records the nullifiers created by a block and marks the notes they consume.

use miden_node_db::sqlite::{InList, WriteTx};
use miden_node_tracing::miden_instrument;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::Nullifier;

use crate::COMPONENT;
use crate::db::utils::get_nullifier_prefix;
use crate::errors::DatabaseError;

const SQL_MARK_NOTES_CONSUMED: &str = include_str!("mark_notes_consumed.sql");
const SQL_INSERT_NULLIFIER: &str = include_str!("insert_nullifier.sql");

/// Inserts the nullifiers created by a block, and marks the notes they consume as consumed at that
/// block.
///
/// # Parameters
/// * `nullifiers`: List of nullifiers to insert
///     - Limit: 0 <= count <= 1000
/// * `block_num`: Block number to associate with the nullifiers
///
/// # Returns
///
/// The number of affected rows, counting both the consumed notes and the inserted nullifiers.
#[miden_instrument(
    target = COMPONENT,
    err,
)]
pub(crate) fn insert_nullifiers_for_block(
    tx: &WriteTx<'_>,
    nullifiers: &[Nullifier],
    block_num: BlockNumber,
) -> Result<usize, DatabaseError> {
    let consumed = InList::from_values(nullifiers);

    let mut count = tx.execute(SQL_MARK_NOTES_CONSUMED, &[&block_num, &consumed])?;

    for nullifier in nullifiers {
        let prefix = get_nullifier_prefix(nullifier);
        count += tx.execute(SQL_INSERT_NULLIFIER, &[nullifier, &prefix, &block_num])?;
    }

    Ok(count)
}
