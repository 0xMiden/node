//! Returns the assets in an account's vault as of a block.

use miden_node_db::sqlite::ReadTx;
use miden_node_proto::domain::account::AccountVaultDetails;
use miden_protocol::account::AccountId;
use miden_protocol::asset::Asset;
use miden_protocol::block::BlockNumber;

use crate::errors::DatabaseError;

const SQL: &str = include_str!("select_vault_at_block.sql");

/// Query vault assets at a specific block by finding the most recent update for each `vault_key`.
///
/// The read is bounded to [`AccountVaultDetails::MAX_RETURN_ENTRIES`] + 1 rows so an over-the-limit
/// vault can be detected without materializing the whole set.
pub(crate) fn select_vault_at_block(
    tx: &ReadTx<'_>,
    account_id: AccountId,
    block_num: BlockNumber,
) -> Result<Vec<Asset>, DatabaseError> {
    let limit =
        i64::try_from(AccountVaultDetails::MAX_RETURN_ENTRIES + 1).expect("should fit within i64");

    // A NULL asset marks a removal, and is filtered out here.
    Ok(tx
        .query(SQL, &[&account_id, &block_num, &limit], |row| row.get::<Option<Asset>>(0))?
        .into_iter()
        .flatten()
        .collect())
}
