//! Bounded pages of target-state storage-map updates.

use std::num::NonZeroUsize;
use std::ops::RangeInclusive;

use miden_node_db::sqlite::ReadTx;
use miden_protocol::Word;
use miden_protocol::account::{AccountId, StorageMapKey, StorageSlotName};
use miden_protocol::block::BlockNumber;

use super::{StorageMapValue, check_account_history_target};
use crate::errors::DatabaseError;

/// Internal continuation position; never exposed in a synchronization response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageMapCursor {
    pub(crate) block_num: BlockNumber,
    pub(crate) slot_name: StorageSlotName,
    pub(crate) key: StorageMapKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageMapUpdatesPage {
    pub values: Vec<StorageMapValue>,
    pub next_cursor: Option<StorageMapCursor>,
}

/// Selects the target value of each public-account map key changed in the inclusive range.
///
/// Preserves zero-value deletions and checks retention in the page snapshot. The block,
/// slot, and key cursor permits continuation within one block.
pub(crate) fn select_account_storage_map_updates_v2(
    tx: &ReadTx<'_>,
    account_id: AccountId,
    range: RangeInclusive<BlockNumber>,
    cursor: Option<StorageMapCursor>,
    page_size: NonZeroUsize,
) -> Result<StorageMapUpdatesPage, DatabaseError> {
    if !account_id.is_public() {
        return Err(DatabaseError::AccountNotPublic(account_id));
    }
    if range.is_empty() {
        return Err(DatabaseError::InvalidBlockRange { from: *range.start(), to: *range.end() });
    }
    check_account_history_target(tx, *range.end())?;
    let limit = page_size.get();
    let query_limit = i64::try_from(limit.saturating_add(1)).expect("page size fits within i64");
    let map_row = |row: &miden_node_db::sqlite::Row<'_>| {
        Ok(StorageMapValue {
            block_num: row.get::<BlockNumber>(0)?,
            slot_name: row.get::<StorageSlotName>(1)?,
            key: row.get::<StorageMapKey>(2)?,
            value: row.get::<Word>(3)?,
        })
    };
    let mut values = match cursor {
        None => tx.query(
            include_str!("select_page.sql"),
            &[&account_id, range.start(), range.end(), &query_limit],
            map_row,
        )?,
        Some(cursor) => tx.query(
            include_str!("select_page_after.sql"),
            &[
                &account_id,
                range.start(),
                range.end(),
                &cursor.block_num,
                &cursor.slot_name,
                &cursor.key,
                &query_limit,
            ],
            map_row,
        )?,
    };
    let has_more = values.len() > limit;
    values.truncate(limit);
    let next_cursor = has_more.then(|| {
        let last = values.last().expect("a continued page cannot be empty");
        StorageMapCursor {
            block_num: last.block_num,
            slot_name: last.slot_name.clone(),
            key: last.key,
        }
    });
    Ok(StorageMapUpdatesPage { values, next_cursor })
}
