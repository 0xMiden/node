use std::mem::size_of;
use std::ops::RangeInclusive;

use miden_node_utils::limiter::MAX_RESPONSE_PAYLOAD_BYTES;
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::asset::{Asset, AssetId};
use miden_protocol::block::BlockNumber;

use super::ReadTransaction;
use crate::db::AccountVaultValue;
use crate::db::pagination::{Page, complete_blocks_page};
use crate::errors::DatabaseError;

const SQL: &str = include_str!("query.sql");

impl ReadTransaction<'_> {
    /// Returns the page of vault updates that the public account `account_id` made within
    /// `block_range`, ordered by block number.
    ///
    /// The page starts at the beginning of `block_range`, and its row limit derives from the
    /// response payload limit. A page never splits a block, so a block with more updates than the
    /// row limit fails with [`DatabaseError::BlockExceedsPageLimit`] instead of being skipped.
    pub fn select_account_vault_assets(
        &self,
        account_id: AccountId,
        block_range: RangeInclusive<BlockNumber>,
    ) -> Result<Page<AccountVaultValue, BlockNumber>, DatabaseError> {
        // The protocol does not define these limits. Derive a conservative row limit from the
        // response payload limit.
        const ROW_OVERHEAD_BYTES: usize = 2 * size_of::<Word>() + size_of::<u32>(); // key + asset + block_num
        const MAX_ROWS: usize = MAX_RESPONSE_PAYLOAD_BYTES / ROW_OVERHEAD_BYTES;

        if !account_id.is_public() {
            return Err(DatabaseError::AccountNotPublic(account_id));
        }

        let (block_from, block_to) = block_range.into_inner();
        if block_from > block_to {
            return Err(DatabaseError::InvalidBlockRange { from: block_from, to: block_to });
        }

        let limit = i64::try_from(MAX_ROWS + 1).expect("should fit within i64");
        let rows =
            self.inner.query(SQL, &[&account_id, &block_from, &block_to, &limit], |row| {
                Ok((row.get::<BlockNumber>(0)?, row.get::<Word>(1)?, row.get::<Option<Asset>>(2)?))
            })?;

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

        complete_blocks_page(values, MAX_ROWS, |value| value.block_num)
    }
}
