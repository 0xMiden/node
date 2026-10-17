//! Writes a versioned account storage-map value.

use miden_node_db::sqlite::WriteTx;
use miden_protocol::Word;
use miden_protocol::account::{AccountId, StorageMapKey, StorageSlotName};
use miden_protocol::block::BlockNumber;

use crate::db::queries::VALID_FOREVER;
use crate::errors::DatabaseError;

const SQL_CLOSE: &str = include_str!("close_storage_map_value_validity.sql");
const SQL_INSERT: &str = include_str!("insert_storage_map_value.sql");

/// Inserts a versioned account storage-map value.
///
/// The new row is inserted open-ended, and any previous open row for the same
/// `(account_id, slot_name, key)` tuple has its validity interval closed at `block_num` first.
///
/// # Returns
///
/// The total number of inserted and invalidated rows.
///
/// # Errors
///
/// Returns an error if the previous row cannot be invalidated or the new row cannot be inserted.
pub(crate) fn insert_storage_map_value(
    tx: &WriteTx<'_>,
    account_id: AccountId,
    block_num: BlockNumber,
    slot_name: &StorageSlotName,
    key: StorageMapKey,
    value: Word,
) -> Result<usize, DatabaseError> {
    insert_storage_map_value_inner(tx, account_id, block_num, slot_name, key, value, true)
}

/// Inserts a versioned account storage-map value with optional previous-row invalidation.
///
/// `invalidate_previous` may be disabled when inserting state for a new account, for which no
/// previous open row can exist. The inserted row is always open-ended.
///
/// # Returns
///
/// The total number of inserted and invalidated rows.
///
/// # Errors
///
/// Returns an error if the requested invalidation or insertion fails.
pub(super) fn insert_storage_map_value_inner(
    tx: &WriteTx<'_>,
    account_id: AccountId,
    block_num: BlockNumber,
    slot_name: &StorageSlotName,
    key: StorageMapKey,
    value: Word,
    invalidate_previous: bool,
) -> Result<usize, DatabaseError> {
    let mut count = 0;
    if invalidate_previous {
        count +=
            tx.execute(SQL_CLOSE, &[&block_num, &account_id, slot_name, &key, &VALID_FOREVER])?;
    }

    count += tx
        .execute(SQL_INSERT, &[&account_id, &block_num, slot_name, &key, &value, &VALID_FOREVER])?;

    Ok(count)
}
