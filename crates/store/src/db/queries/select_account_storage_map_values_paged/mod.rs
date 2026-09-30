//! Returns the storage map updates of an account within a block range.

use std::ops::RangeInclusive;

use miden_node_db::sqlite::ReadTx;
use miden_protocol::Word;
use miden_protocol::account::{AccountId, StorageMapKey, StorageSlotName};
use miden_protocol::block::BlockNumber;

use crate::errors::DatabaseError;

const SQL: &str = include_str!("select_account_storage_map_values_paged.sql");

/// A storage map value at the block that wrote it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageMapValue {
    pub block_num: BlockNumber,
    pub slot_name: StorageSlotName,
    pub key: StorageMapKey,
    pub value: Word,
}

/// Page of storage map values returned by [`select_account_storage_map_values_paged`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageMapValuesPage {
    /// Highest block number included in `rows`. If the page is empty, this will be `block_from`.
    pub last_block_included: BlockNumber,
    /// Storage map values
    pub values: Vec<StorageMapValue>,
}

/// Select account storage map values within a block range (inclusive).
///
/// ## Parameters
///
/// * `account_id`: Account ID to query
/// * `block_range`: Range of block numbers (inclusive)
/// * `limit`: Maximum number of values in the page
///
/// ## Response
///
/// * Response payload size: 0 <= size <= 2MB
/// * Storage map values per response: 0 <= count <= (2MB / (2*Word + u32 + u8)) + 1
///
/// If the rows exceed `limit`, the page does not include the last block.
pub(crate) fn select_account_storage_map_values_paged(
    tx: &ReadTx<'_>,
    account_id: AccountId,
    block_range: RangeInclusive<BlockNumber>,
    limit: usize,
) -> Result<StorageMapValuesPage, DatabaseError> {
    if !account_id.is_public() {
        return Err(DatabaseError::AccountNotPublic(account_id));
    }

    if block_range.is_empty() {
        return Err(DatabaseError::InvalidBlockRange {
            from: *block_range.start(),
            to: *block_range.end(),
        });
    }

    let row_limit = i64::try_from(limit + 1).expect("limit fits within i64");
    let mut values =
        tx.query(SQL, &[&account_id, block_range.start(), block_range.end(), &row_limit], |row| {
            Ok(StorageMapValue {
                block_num: row.get::<BlockNumber>(0)?,
                slot_name: row.get::<StorageSlotName>(1)?,
                key: row.get::<StorageMapKey>(2)?,
                value: row.get::<Word>(3)?,
            })
        })?;

    // If we got more rows than the limit, the last block may be incomplete so we drop it entirely
    // and derive last_block_included from the remaining rows.
    let last_block_included = if let Some(last_block_num) = values.last().map(|v| v.block_num)
        && values.len() > limit
    {
        values.retain(|v| v.block_num != last_block_num);
        values.last().map_or(*block_range.start(), |v| v.block_num)
    } else {
        *block_range.end()
    };

    Ok(StorageMapValuesPage { last_block_included, values })
}
