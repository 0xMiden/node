//! Returns the storage map updates of an account within a block range.

use std::ops::RangeInclusive;

use miden_node_db::sqlite::ReadTx;
use miden_protocol::Word;
use miden_protocol::account::{AccountId, StorageMapKey, StorageSlotName};
use miden_protocol::block::BlockNumber;

use crate::db::pagination::{Page, Paginated, complete_blocks_page};
use crate::errors::DatabaseError;
use crate::state::ScopedBlockRange;

const SQL: &str = include_str!("select_account_storage_map_values_paged.sql");

/// A storage map value at the block that wrote it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageMapValue {
    pub block_num: BlockNumber,
    pub slot_name: StorageSlotName,
    pub key: StorageMapKey,
    pub value: Word,
}

/// Page of storage map values returned by
/// [`StateView::sync_account_storage_maps`](crate::StateView::sync_account_storage_maps).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageMapValuesPage {
    /// Highest block number that the page covers completely.
    pub last_block_included: BlockNumber,
    /// Storage map values
    pub values: Vec<StorageMapValue>,
}

/// Paginated query over the storage map values an account wrote within an inclusive block range,
/// ordered by block number.
///
/// A page holds at most `limit` values and never splits a block, so the block number can serve as
/// the cursor. A block with more than `limit` values can never fit in a page, so it fails with
/// [`DatabaseError::BlockExceedsPageLimit`] instead of being skipped.
#[derive(Debug, Clone)]
pub(crate) struct AccountStorageMapValuesPaged {
    account_id: AccountId,
    block_range: RangeInclusive<BlockNumber>,
    limit: usize,
}

impl AccountStorageMapValuesPaged {
    /// Creates the query for `account_id` within `block_range`, with at most `limit` values per
    /// page.
    pub(crate) fn new(account_id: AccountId, block_range: ScopedBlockRange, limit: usize) -> Self {
        Self {
            account_id,
            block_range: block_range.into_inner(),
            limit,
        }
    }
}

impl Paginated for AccountStorageMapValuesPaged {
    type Item = StorageMapValue;
    type Cursor = BlockNumber;

    fn page(
        &self,
        tx: &ReadTx<'_>,
        after: Option<&BlockNumber>,
    ) -> Result<Page<StorageMapValue, BlockNumber>, DatabaseError> {
        if !self.account_id.is_public() {
            return Err(DatabaseError::AccountNotPublic(self.account_id));
        }

        let block_from = after.map_or(*self.block_range.start(), |block| block.child());
        let block_to = *self.block_range.end();
        if block_from > block_to {
            return Err(DatabaseError::InvalidBlockRange { from: block_from, to: block_to });
        }

        let row_limit = i64::try_from(self.limit + 1).expect("limit fits within i64");
        let values =
            tx.query(SQL, &[&self.account_id, &block_from, &block_to, &row_limit], |row| {
                Ok(StorageMapValue {
                    block_num: row.get::<BlockNumber>(0)?,
                    slot_name: row.get::<StorageSlotName>(1)?,
                    key: row.get::<StorageMapKey>(2)?,
                    value: row.get::<Word>(3)?,
                })
            })?;

        complete_blocks_page(values, self.limit, |value| value.block_num)
    }
}
