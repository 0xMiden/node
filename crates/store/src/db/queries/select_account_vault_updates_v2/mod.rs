//! Returns a bounded page of final vault values for keys changed within a block range.

use std::num::NonZeroUsize;

use miden_node_db::sqlite::ReadTx;
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::asset::{Asset, AssetId};
use miden_protocol::block::BlockNumber;

use crate::db::pagination::{Page, key_cursor};
use crate::db::queries::check_account_history_target;
use crate::db::{AccountVaultCursor, AccountVaultValue, AccountVaultValuesPage};
use crate::errors::DatabaseError;
use crate::state::ScopedBlockRange;

/// Target-state vault updates in block-and-key order, including continuations within a block.
///
/// Validity intervals remove intermediate updates while retaining values superseded after the
/// target. Each page checks account-history retention in its read transaction.
pub fn account_vault_updates_page(
    tx: &ReadTx<'_>,
    account: AccountId,
    range: ScopedBlockRange,
    cursor: Option<&AccountVaultCursor>,
    page_size: NonZeroUsize,
) -> Result<AccountVaultValuesPage, DatabaseError> {
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
    let key = key_cursor(next.map(|next| Word::from(next.vault_key)).as_ref());
    let limit =
        i64::try_from(page_size.get().saturating_add(1)).expect("page size fits within i64");
    let rows = tx.query(
        include_str!("select_account_vault_updates_v2.sql"),
        &[&account, range.end(), &block, &key, &limit],
        |row| Ok((row.get::<BlockNumber>(0)?, row.get::<Word>(1)?, row.get::<Option<Asset>>(2)?)),
    )?;
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
    let page = Page::from_overflow(values, page_size, |value| AccountVaultCursor {
        block_num: value.block_num,
        vault_key: value.vault_key,
    });
    Ok(AccountVaultValuesPage {
        values: page.items,
        next_cursor: page.next,
    })
}
