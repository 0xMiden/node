//! Returns a bounded page of final vault values for keys changed within a block range.

use std::num::NonZeroUsize;
use std::ops::RangeInclusive;

use miden_node_db::sqlite::ReadTx;
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::asset::{Asset, AssetId};
use miden_protocol::block::BlockNumber;

use crate::db::queries::check_account_history_target;
use crate::db::{AccountVaultCursor, AccountVaultValue, AccountVaultValuesPage};
use crate::errors::DatabaseError;

const SQL_PAGE: &str = include_str!("select_account_vault_updates_v2.sql");
const SQL_PAGE_AFTER: &str = include_str!("select_account_vault_updates_v2_after.sql");

/// Selects a bounded page containing the final update at `block_range.end()` for every vault key
/// changed within the inclusive block range.
///
/// Vault rows are valid in `[block_num, valid_until)`. Requiring `valid_until > block_to` removes
/// intermediate updates while retaining a historical value that was superseded after the target.
/// Results use the table's `(account_id, block_num, vault_key)` primary-key order so they can be
/// continued with a stable keyset cursor without response-size accounting.
pub(crate) fn select_account_vault_updates_v2(
    tx: &ReadTx<'_>,
    account_id: AccountId,
    block_range: RangeInclusive<BlockNumber>,
    cursor: Option<AccountVaultCursor>,
    page_size: NonZeroUsize,
) -> Result<AccountVaultValuesPage, DatabaseError> {
    if !account_id.is_public() {
        return Err(DatabaseError::AccountNotPublic(account_id));
    }

    if block_range.is_empty() {
        return Err(DatabaseError::InvalidBlockRange {
            from: *block_range.start(),
            to: *block_range.end(),
        });
    }

    check_account_history_target(tx, *block_range.end())?;

    let limit = page_size.get();
    let query_limit = i64::try_from(limit.saturating_add(1)).expect("page size fits within i64");
    let map_row = |row: &miden_node_db::sqlite::Row<'_>| {
        Ok((row.get::<BlockNumber>(0)?, row.get::<Word>(1)?, row.get::<Option<Asset>>(2)?))
    };
    // The cursor supplies the SQL lower bound. Use the first page if it precedes the range.
    let mut rows = match cursor.filter(|cursor| cursor.block_num >= *block_range.start()) {
        Some(cursor) => tx.query(
            SQL_PAGE_AFTER,
            &[
                &account_id,
                block_range.end(),
                &cursor.block_num,
                &Word::from(cursor.vault_key),
                &query_limit,
            ],
            map_row,
        )?,
        None => tx.query(
            SQL_PAGE,
            &[&account_id, block_range.start(), block_range.end(), &query_limit],
            map_row,
        )?,
    };
    let has_more = rows.len() > limit;
    rows.truncate(limit);
    let values = rows
        .into_iter()
        .map(|(block_num, vault_key, asset)| {
            Ok(AccountVaultValue {
                block_num,
                vault_key: AssetId::try_from(vault_key)?,
                asset,
            })
        })
        .collect::<Result<Vec<_>, DatabaseError>>()?;
    let next_cursor = has_more.then(|| {
        let last = values.last().expect("a page with more rows cannot be empty");
        AccountVaultCursor {
            block_num: last.block_num,
            vault_key: last.vault_key,
        }
    });

    Ok(AccountVaultValuesPage { values, next_cursor })
}
