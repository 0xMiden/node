//! Returns a bounded page of final vault values for keys changed within a block range.

use std::num::NonZeroUsize;
use std::ops::RangeInclusive;

use miden_node_db::sqlite::ReadTx;
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::asset::{Asset, AssetId};
use miden_protocol::block::BlockNumber;

use crate::db::pagination::{Page, Paginated, key_cursor};
use crate::db::queries::check_account_history_target;
use crate::db::{AccountVaultCursor, AccountVaultValue};
use crate::errors::DatabaseError;
use crate::state::ScopedBlockRange;

/// Target-state vault updates in block-and-key order, including continuations within a block.
///
/// Validity intervals remove intermediate updates while retaining values superseded after the
/// target. Each page checks account-history retention in its read transaction.
pub(crate) struct AccountVaultUpdatesV2 {
    account_id: AccountId,
    range: RangeInclusive<BlockNumber>,
    page_size: NonZeroUsize,
}

impl AccountVaultUpdatesV2 {
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

impl Paginated for AccountVaultUpdatesV2 {
    type Item = AccountVaultValue;
    type Cursor = Option<AccountVaultCursor>;

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
        let key = key_cursor(next.map(|next| Word::from(next.vault_key)).as_ref());
        let limit = i64::try_from(self.page_size.get().saturating_add(1))
            .expect("page size fits within i64");
        let rows = tx.query(
            include_str!("select_account_vault_updates_v2.sql"),
            &[&self.account_id, self.range.end(), &block, &key, &limit],
            |row| {
                Ok((row.get::<BlockNumber>(0)?, row.get::<Word>(1)?, row.get::<Option<Asset>>(2)?))
            },
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
        Ok(Page::from_overflow(values, self.page_size, |value| {
            Some(AccountVaultCursor {
                block_num: value.block_num,
                vault_key: value.vault_key,
            })
        }))
    }
}
