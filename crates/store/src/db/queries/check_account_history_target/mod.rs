//! Checks retention in the same SQLite snapshot as the following page query.

use miden_node_db::sqlite::ReadTx;
use miden_protocol::block::BlockNumber;

use super::HISTORICAL_BLOCK_RETENTION;
use crate::errors::DatabaseError;

/// Checks that the target remains in the retained account-history window.
///
/// Use the same read transaction for this check and the page query so pruning cannot
/// change the database snapshot between validation and selection.
pub(crate) fn check_account_history_target(
    tx: &ReadTx<'_>,
    target: BlockNumber,
) -> Result<(), DatabaseError> {
    let chain_tip = tx
        .query(include_str!("select_chain_tip.sql"), &[], |row| row.get::<BlockNumber>(0))?
        .into_iter()
        .next()
        .ok_or_else(|| DatabaseError::DataCorrupted("block headers table is empty".to_owned()))?;
    let oldest_available = chain_tip
        .checked_sub(HISTORICAL_BLOCK_RETENTION)
        .unwrap_or(BlockNumber::GENESIS);
    if target < oldest_available {
        return Err(DatabaseError::BlockPruned { block_num: target, oldest_available });
    }
    Ok(())
}
