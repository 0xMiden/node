//! Returns a page of nullifiers, to rebuild the nullifier tree at startup.

use std::num::NonZeroUsize;

use miden_node_db::sqlite::{ReadTx, Row};
use miden_protocol::block::BlockNumber;
use miden_protocol::note::Nullifier;

use crate::db::NullifierInfo;
use crate::errors::DatabaseError;

const SQL_FIRST_PAGE: &str = include_str!("select_nullifiers_page.sql");
const SQL_AFTER_CURSOR: &str = include_str!("select_nullifiers_page_after.sql");

/// Page of nullifiers returned by [`select_nullifiers_paged`].
#[derive(Debug)]
pub struct NullifiersPage {
    /// The nullifiers in this page.
    pub nullifiers: Vec<NullifierInfo>,
    /// If `Some`, there are more results. Use this as the `after_nullifier` for the next page.
    pub next_cursor: Option<Nullifier>,
}

/// Selects nullifiers with pagination.
///
/// Returns up to `page_size` nullifiers, starting after `after_nullifier` if provided.
/// Results are ordered by nullifier bytes for stable pagination.
pub(crate) fn select_nullifiers_paged(
    tx: &ReadTx<'_>,
    page_size: NonZeroUsize,
    after_nullifier: Option<Nullifier>,
) -> Result<NullifiersPage, DatabaseError> {
    // Fetch one extra to determine if there are more results
    let limit = i64::try_from(page_size.get() + 1).expect("page size fits within i64");

    let mut nullifiers = match after_nullifier {
        Some(cursor) => tx.query(SQL_AFTER_CURSOR, &[&limit, &cursor], nullifier_info_from_row)?,
        None => tx.query(SQL_FIRST_PAGE, &[&limit], nullifier_info_from_row)?,
    };

    // If we got more than page_size, there are more results
    let next_cursor = if nullifiers.len() > page_size.get() {
        nullifiers.pop(); // Remove the extra element
        nullifiers.last().map(|info| info.nullifier)
    } else {
        None
    };

    Ok(NullifiersPage { nullifiers, next_cursor })
}

/// Maps a `SELECT nullifier, block_num` row to its [`NullifierInfo`].
fn nullifier_info_from_row(row: &Row<'_>) -> Result<NullifierInfo, miden_node_db::DatabaseError> {
    Ok(NullifierInfo {
        nullifier: row.get::<Nullifier>(0)?,
        block_num: row.get::<BlockNumber>(1)?,
    })
}
