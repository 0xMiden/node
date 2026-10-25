//! Bounded pages of target-state storage-map updates.

use std::num::NonZeroUsize;
use std::ops::RangeInclusive;

use miden_node_db::sqlite::ReadTx;
use miden_protocol::Word;
use miden_protocol::account::{AccountId, StorageMapKey, StorageSlotName};
use miden_protocol::block::BlockNumber;

use super::{StorageMapValue, check_account_history_target};
use crate::db::pagination::{Page, Paginated, key_cursor};
use crate::errors::DatabaseError;
use crate::state::ScopedBlockRange;

/// Inclusive position of the first value in the next storage-map page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageMapCursor {
    pub(crate) block_num: BlockNumber,
    pub(crate) slot_name: StorageSlotName,
    pub(crate) key: StorageMapKey,
}

/// A bounded page of target-state storage-map values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageMapUpdatesPage {
    pub values: Vec<StorageMapValue>,
    /// First omitted item, or `None` when the range is complete.
    pub next_cursor: Option<StorageMapCursor>,
}

/// Target-state storage-map updates in block, slot, and key order.
pub(crate) struct AccountStorageMapUpdatesV2 {
    account_id: AccountId,
    range: RangeInclusive<BlockNumber>,
    page_size: NonZeroUsize,
}

impl AccountStorageMapUpdatesV2 {
    pub(crate) fn new(
        account_id: AccountId,
        range: ScopedBlockRange,
        page_size: NonZeroUsize,
    ) -> Self {
        Self {
            account_id,
            range: range.into_inner(),
            page_size,
        }
    }
}

impl Paginated for AccountStorageMapUpdatesV2 {
    type Item = StorageMapValue;
    type Cursor = Option<StorageMapCursor>;

    fn page(
        &self,
        tx: &ReadTx<'_>,
        next: &Self::Cursor,
    ) -> Result<Page<Self::Item, Self::Cursor>, DatabaseError> {
        if !self.account_id.is_public() {
            return Err(DatabaseError::AccountNotPublic(self.account_id));
        }
        if self.range.is_empty() {
            return Err(DatabaseError::InvalidBlockRange {
                from: *self.range.start(),
                to: *self.range.end(),
            });
        }
        check_account_history_target(tx, *self.range.end())?;
        let next = next.as_ref().filter(|next| next.block_num >= *self.range.start());
        let block = next.map_or(*self.range.start(), |next| next.block_num);
        let slot = next.map_or("", |next| next.slot_name.as_str());
        let key = key_cursor(next.map(|next| &next.key));
        let limit = i64::try_from(self.page_size.get().saturating_add(1))
            .expect("page size fits within i64");
        let rows = tx.query(
            include_str!("select_page.sql"),
            &[&self.account_id, self.range.end(), &block, &slot, &key, &limit],
            |row| {
                Ok(StorageMapValue {
                    block_num: row.get::<BlockNumber>(0)?,
                    slot_name: row.get::<StorageSlotName>(1)?,
                    key: row.get::<StorageMapKey>(2)?,
                    value: row.get::<Word>(3)?,
                })
            },
        )?;
        Ok(Page::from_overflow(rows, self.page_size, |row| {
            Some(StorageMapCursor {
                block_num: row.block_num,
                slot_name: row.slot_name.clone(),
                key: row.key,
            })
        }))
    }
}
