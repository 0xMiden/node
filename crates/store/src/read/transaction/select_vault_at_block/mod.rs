use miden_node_proto::domain::account::AccountVaultDetails;
use miden_protocol::account::AccountId;
use miden_protocol::asset::Asset;
use miden_protocol::block::BlockNumber;

use super::ReadTransaction;
use crate::errors::DatabaseError;

const SQL: &str = include_str!("query.sql");

impl ReadTransaction<'_> {
    /// Returns the assets in the vault of `account_id` as of `block_num`, taking the most recent
    /// update of each vault key.
    ///
    /// The read is bounded to [`AccountVaultDetails::MAX_RETURN_ENTRIES`] + 1 rows so an
    /// over-the-limit vault can be detected without materializing the whole set.
    pub fn select_vault_at_block(
        &self,
        account_id: AccountId,
        block_num: BlockNumber,
    ) -> Result<Vec<Asset>, DatabaseError> {
        let limit = i64::try_from(AccountVaultDetails::MAX_RETURN_ENTRIES + 1)
            .expect("should fit within i64");

        Ok(self
            .inner
            .query(SQL, &[&account_id, &block_num, &limit], |row| row.get::<Asset>(0))?)
    }
}
