//! Returns the vault updates of an account within a block range.

use std::mem::size_of;
use std::ops::RangeInclusive;

use miden_node_db::sqlite::ReadTx;
use miden_node_utils::limiter::MAX_RESPONSE_PAYLOAD_BYTES;
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::asset::{Asset, AssetId};
use miden_protocol::block::BlockNumber;

use crate::db::AccountVaultValue;
use crate::errors::DatabaseError;

const SQL: &str = include_str!("select_account_vault_assets.sql");

/// Select account vault assets within a block range (inclusive).
///
/// # Parameters
/// * `account_id`: Account ID to query
/// * `block_range`: Range of block numbers (inclusive)
/// * Response payload size: 0 <= size <= 2MB
/// * Vault assets per response: 0 <= count <= (2MB / (2*Word + u32)) + 1
///
/// # Returns
///
/// The last block that the response covers, and the vault updates. If the rows exceed the payload
/// limit, the response does not include the last block.
pub(crate) fn select_account_vault_assets(
    tx: &ReadTx<'_>,
    account_id: AccountId,
    block_range: RangeInclusive<BlockNumber>,
) -> Result<(BlockNumber, Vec<AccountVaultValue>), DatabaseError> {
    // The protocol does not define these limits. Derive a conservative row limit from the response
    // payload limit.
    const ROW_OVERHEAD_BYTES: usize = 2 * size_of::<Word>() + size_of::<u32>(); // key + asset + block_num
    const MAX_ROWS: usize = MAX_RESPONSE_PAYLOAD_BYTES / ROW_OVERHEAD_BYTES;

    if !account_id.is_public() {
        return Err(DatabaseError::AccountNotPublic(account_id));
    }

    if block_range.is_empty() {
        return Err(DatabaseError::InvalidBlockRange {
            from: *block_range.start(),
            to: *block_range.end(),
        });
    }

    let limit = i64::try_from(MAX_ROWS + 1).expect("should fit within i64");
    let rows =
        tx.query(SQL, &[&account_id, block_range.start(), block_range.end(), &limit], |row| {
            Ok((row.get::<BlockNumber>(0)?, row.get::<Word>(1)?, row.get::<Option<Asset>>(2)?))
        })?;

    let mut values = rows
        .into_iter()
        .map(|(block_num, vault_key, asset)| {
            Ok(AccountVaultValue {
                block_num,
                vault_key: AssetId::try_from(vault_key)?,
                asset,
            })
        })
        .collect::<Result<Vec<_>, DatabaseError>>()?;

    // If we got more rows than the limit, the last block may be incomplete so we drop it entirely
    // and derive last_block_included from the remaining rows. The rows are ordered by block number,
    // so the rows of the last block are a suffix and a binary search finds where it starts.
    let last_block_included = if let Some(last_block_num) = values.last().map(|v| v.block_num)
        && values.len() > MAX_ROWS
    {
        let complete_len = values.partition_point(|v| v.block_num < last_block_num);
        values.truncate(complete_len);
        values.last().map_or(*block_range.start(), |v| v.block_num)
    } else {
        *block_range.end()
    };

    Ok((last_block_included, values))
}
