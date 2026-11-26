//! Bounded pages of target-state storage-map updates.

use std::num::NonZeroUsize;

use miden_node_db::sqlite::ReadTx;
use miden_protocol::Word;
use miden_protocol::account::{AccountId, StorageMapKey, StorageSlotName};
use miden_protocol::block::BlockNumber;

use super::{StorageMapValue, check_account_history_target};
use crate::db::pagination::{Page, key_cursor};
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
pub fn account_storage_map_updates_page(
    tx: &ReadTx<'_>,
    account: AccountId,
    range: ScopedBlockRange,
    cursor: Option<&StorageMapCursor>,
    page_size: NonZeroUsize,
) -> Result<StorageMapUpdatesPage, DatabaseError> {
    let range = range.into_inner();
    if !account.is_public() {
        return Err(DatabaseError::AccountNotPublic(account));
    }
    if range.is_empty() {
        return Err(DatabaseError::InvalidBlockRange { from: *range.start(), to: *range.end() });
    }
    check_account_history_target(tx, *range.end())?;
    let next = cursor.filter(|next| next.block_num >= *range.start());
    let block = next.map_or(*range.start(), |next| next.block_num);
    let slot = next.map_or("", |next| next.slot_name.as_str());
    let key = key_cursor(next.map(|next| &next.key));
    let limit =
        i64::try_from(page_size.get().saturating_add(1)).expect("page size fits within i64");
    let rows = tx.query(
        include_str!("select_page.sql"),
        &[&account, range.end(), &block, &slot, &key, &limit],
        |row| {
            Ok(StorageMapValue {
                block_num: row.get::<BlockNumber>(0)?,
                slot_name: row.get::<StorageSlotName>(1)?,
                key: row.get::<StorageMapKey>(2)?,
                value: row.get::<Word>(3)?,
            })
        },
    )?;
    let page = Page::from_overflow(rows, page_size, |row| StorageMapCursor {
        block_num: row.block_num,
        slot_name: row.slot_name.clone(),
        key: row.key,
    });
    Ok(StorageMapUpdatesPage {
        values: page.items,
        next_cursor: page.next,
    })
}
