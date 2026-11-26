use std::ops::RangeInclusive;

use miden_protocol::Word;
use miden_protocol::account::{AccountId, StorageMapKey, StorageSlotName};
use miden_protocol::block::BlockNumber;

use super::ReadTransaction;
use crate::db::pagination::{Page, complete_blocks_page};
use crate::errors::DatabaseError;

const SQL: &str = include_str!("query.sql");

/// A storage map value at the block that wrote it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageMapValue {
    pub block_num: BlockNumber,
    pub slot_name: StorageSlotName,
    pub key: StorageMapKey,
    pub value: Word,
}

impl ReadTransaction<'_> {
    /// Returns the page of storage map values that the public account `account_id` wrote within
    /// `block_range`, ordered by block number.
    ///
    /// The page starts at the beginning of `block_range` and holds at most `limit` values. A page
    /// never splits a block, so a block with more than `limit` values can never fit in a page and
    /// fails with [`DatabaseError::BlockExceedsPageLimit`] instead of being skipped.
    pub fn select_account_storage_map_values_paged(
        &self,
        account_id: AccountId,
        block_range: RangeInclusive<BlockNumber>,
        limit: usize,
    ) -> Result<Page<StorageMapValue, BlockNumber>, DatabaseError> {
        if !account_id.is_public() {
            return Err(DatabaseError::AccountNotPublic(account_id));
        }

        let (block_from, block_to) = block_range.into_inner();
        if block_from > block_to {
            return Err(DatabaseError::InvalidBlockRange { from: block_from, to: block_to });
        }

        let row_limit = i64::try_from(limit + 1).expect("limit fits within i64");
        let values =
            self.inner
                .query(SQL, &[&account_id, &block_from, &block_to, &row_limit], |row| {
                    Ok(StorageMapValue {
                        block_num: row.get::<BlockNumber>(0)?,
                        slot_name: row.get::<StorageSlotName>(1)?,
                        key: row.get::<StorageMapKey>(2)?,
                        value: row.get::<Word>(3)?,
                    })
                })?;

        complete_blocks_page(values, limit, |value| value.block_num)
    }
}
