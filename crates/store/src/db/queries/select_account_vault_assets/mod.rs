//! Returns the vault updates of an account within a block range.

use std::mem::size_of;

use miden_node_db::sqlite::ReadTx;
use miden_node_utils::limiter::MAX_RESPONSE_PAYLOAD_BYTES;
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::asset::{Asset, AssetId};
use miden_protocol::block::BlockNumber;

use crate::db::AccountVaultValue;
use crate::db::pagination::{Page, Paginated, complete_blocks_page};
use crate::errors::DatabaseError;
use crate::state::ScopedBlockNum;

const SQL: &str = include_str!("select_account_vault_assets.sql");

/// Paginated query over the vault updates of an account up to `block_to`, ordered by block number.
///
/// The cursor is the block where a page starts. The row limit of a page derives from the response
/// payload limit. A page never splits a block, so a block with more updates than the row limit
/// fails with [`DatabaseError::BlockExceedsPageLimit`] instead of being skipped.
#[derive(Debug, Clone)]
pub(crate) struct AccountVaultAssets {
    account_id: AccountId,
    block_to: BlockNumber,
}

impl AccountVaultAssets {
    /// Creates the query for `account_id` up to and including `block_to`.
    pub(crate) fn new(account_id: AccountId, block_to: ScopedBlockNum) -> Self {
        Self { account_id, block_to: *block_to }
    }
}

impl Paginated for AccountVaultAssets {
    type Item = AccountVaultValue;
    type Cursor = BlockNumber;

    fn page(
        &self,
        tx: &ReadTx<'_>,
        next: &BlockNumber,
    ) -> Result<Page<AccountVaultValue, BlockNumber>, DatabaseError> {
        // The protocol does not define these limits. Derive a conservative row limit from the
        // response payload limit.
        const ROW_OVERHEAD_BYTES: usize = 2 * size_of::<Word>() + size_of::<u32>(); // key + asset + block_num
        const MAX_ROWS: usize = MAX_RESPONSE_PAYLOAD_BYTES / ROW_OVERHEAD_BYTES;

        if !self.account_id.is_public() {
            return Err(DatabaseError::AccountNotPublic(self.account_id));
        }

        let (block_from, block_to) = (*next, self.block_to);
        if block_from > block_to {
            return Err(DatabaseError::InvalidBlockRange { from: block_from, to: block_to });
        }

        let limit = i64::try_from(MAX_ROWS + 1).expect("should fit within i64");
        let rows = tx.query(SQL, &[&self.account_id, &block_from, &block_to, &limit], |row| {
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
