//! Shared pagination for store reads.

use std::num::NonZeroUsize;

use miden_node_db::sqlite::ReadTx;
use miden_protocol::block::BlockNumber;

use crate::errors::DatabaseError;

// PAGE
// ================================================================================================

/// One page of results from a [`Paginated`] query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Page<T, C> {
    /// The items in this page, in cursor order.
    pub items: Vec<T>,
    /// The cursor to pass as `after` to read the next page, or `None` if this is the last page.
    pub next: Option<C>,
}

impl<T, C> Page<T, C> {
    /// Builds a page from up to `page_size + 1` rows in cursor order.
    ///
    /// Queries fetch one row beyond the page size to learn whether another page exists without a
    /// separate count. The extra row is dropped, and the last remaining row becomes the cursor.
    pub fn from_overflow(
        mut rows: Vec<T>,
        page_size: NonZeroUsize,
        cursor_of: impl Fn(&T) -> C,
    ) -> Self {
        let next = if rows.len() > page_size.get() {
            rows.truncate(page_size.get());
            rows.last().map(cursor_of)
        } else {
            None
        };
        Self { items: rows, next }
    }
}

/// Builds a page from up to `limit + 1` rows in block order, keeping only complete blocks.
///
/// Block range queries use the block number as the cursor, so a page must never split a block.
/// When the rows exceed `limit`, the last block may be incomplete, so its rows are dropped and
/// `next` becomes the block before it. If every row belongs to that last block, the block alone
/// exceeds `limit` and can never fit in a page, so this returns
/// [`DatabaseError::BlockExceedsPageLimit`] instead of an empty page that would stall pagination.
pub(crate) fn complete_blocks_page<T>(
    mut rows: Vec<T>,
    limit: usize,
    block_of: impl Fn(&T) -> BlockNumber,
) -> Result<Page<T, BlockNumber>, DatabaseError> {
    let Some(last_block) = rows.get(limit).map(&block_of) else {
        return Ok(Page { items: rows, next: None });
    };

    // The rows of the last block are a suffix, so a binary search finds where they start.
    rows.truncate(rows.partition_point(|row| block_of(row) < last_block));
    if rows.is_empty() {
        return Err(DatabaseError::BlockExceedsPageLimit { block_num: last_block });
    }

    let next = last_block
        .parent()
        .expect("the page holds rows of a block before the last block");
    Ok(Page { items: rows, next: Some(next) })
}

// PAGINATED
// ================================================================================================

/// A read query that returns its results one page at a time.
///
/// Implementations return items in cursor order, and `page(tx, Some(cursor))` returns only items
/// after `cursor`. A non-empty page must move the cursor forward, and an empty page must set `next`
/// to `None`, because [`Db::pages`](super::Db::pages) relies on both to terminate. When no item can
/// fit in a page, such as a block with more rows than the page limit, `page` returns an error
/// instead of an empty page that would stall pagination.
pub(crate) trait Paginated: Send + Sync + 'static {
    /// One result of the query.
    type Item: Send + 'static;
    /// The position of an item in the query order.
    type Cursor: Send + 'static;

    /// Returns the page after `after`, or the first page when `after` is `None`.
    fn page(
        &self,
        tx: &ReadTx<'_>,
        after: Option<&Self::Cursor>,
    ) -> Result<Page<Self::Item, Self::Cursor>, DatabaseError>;
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use assert_matches::assert_matches;
    use miden_protocol::block::BlockNumber;

    use super::{Page, complete_blocks_page};
    use crate::errors::DatabaseError;

    fn blocks(values: &[u32]) -> Vec<BlockNumber> {
        values.iter().copied().map(BlockNumber::from).collect()
    }

    #[test]
    fn from_overflow_without_extra_row_is_the_last_page() {
        let page = Page::from_overflow(vec![1, 2, 3], NonZeroUsize::new(3).unwrap(), |row| *row);

        assert_eq!(page, Page { items: vec![1, 2, 3], next: None });
    }

    #[test]
    fn from_overflow_drops_the_extra_row_and_points_at_the_last_item() {
        let page =
            Page::from_overflow(vec![1, 2, 3, 4], NonZeroUsize::new(3).unwrap(), |row| *row * 10);

        assert_eq!(page, Page { items: vec![1, 2, 3], next: Some(30) });
    }

    #[test]
    fn complete_blocks_page_within_limit_is_the_last_page() {
        let page = complete_blocks_page(blocks(&[1, 2, 2]), 3, |block| *block).unwrap();

        assert_eq!(page, Page { items: blocks(&[1, 2, 2]), next: None });
    }

    #[test]
    fn complete_blocks_page_drops_the_incomplete_last_block() {
        let page = complete_blocks_page(blocks(&[1, 2, 5, 5]), 3, |block| *block).unwrap();

        // Blocks 3 and 4 have no rows, so the page covers them completely.
        assert_eq!(
            page,
            Page {
                items: blocks(&[1, 2]),
                next: Some(4.into())
            }
        );
    }

    #[test]
    fn complete_blocks_page_rejects_a_block_larger_than_the_limit() {
        let result = complete_blocks_page(blocks(&[7, 7, 7]), 2, |block| *block);

        assert_matches!(
            result,
            Err(DatabaseError::BlockExceedsPageLimit { block_num }) if block_num == 7.into()
        );
    }
}
