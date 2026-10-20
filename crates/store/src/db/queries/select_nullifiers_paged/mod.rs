//! Returns pages of nullifiers, to rebuild the nullifier tree at startup.

use std::num::NonZeroUsize;

use miden_node_db::sqlite::{ReadTx, Row};
use miden_protocol::block::BlockNumber;
use miden_protocol::note::Nullifier;

use crate::db::NullifierInfo;
use crate::db::pagination::{Page, Paginated, key_cursor};
use crate::errors::DatabaseError;

const SQL: &str = include_str!("select_nullifiers_page.sql");

/// Paginated query over all nullifiers, ordered by nullifier.
///
/// The cursor is the nullifier where a page starts, or `None` for the first nullifier.
#[derive(Debug, Clone, Copy)]
pub(crate) struct NullifiersPaged {
    /// Maximum number of nullifiers in a page.
    pub page_size: NonZeroUsize,
}

impl Paginated for NullifiersPaged {
    type Item = NullifierInfo;
    type Cursor = Option<Nullifier>;

    fn page(
        &self,
        tx: &ReadTx<'_>,
        next: &Option<Nullifier>,
    ) -> Result<Page<NullifierInfo, Option<Nullifier>>, DatabaseError> {
        // Fetch one extra to determine if there are more results
        let limit = i64::try_from(self.page_size.get() + 1).expect("page size fits within i64");

        let nullifiers =
            tx.query(SQL, &[&limit, &key_cursor(next.as_ref())], nullifier_info_from_row)?;

        Ok(Page::from_overflow(nullifiers, self.page_size, |info| Some(info.nullifier)))
    }
}

/// Maps a `SELECT nullifier, block_num` row to its [`NullifierInfo`].
fn nullifier_info_from_row(row: &Row<'_>) -> Result<NullifierInfo, miden_node_db::DatabaseError> {
    Ok(NullifierInfo {
        nullifier: row.get::<Nullifier>(0)?,
        block_num: row.get::<BlockNumber>(1)?,
    })
}
