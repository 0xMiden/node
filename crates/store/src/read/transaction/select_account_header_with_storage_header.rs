use miden_protocol::account::{AccountHeader, AccountId, AccountStorageHeader};
use miden_protocol::block::BlockNumber;

use super::ReadTransaction;
use crate::DatabaseError;

impl ReadTransaction<'_> {
    /// Returns the account header and storage header of `account_id` as of `block_num`, or `None`
    /// if the account does not exist at that block or is private.
    pub fn select_account_header_with_storage_header(
        &self,
        account_id: AccountId,
        block_num: BlockNumber,
    ) -> Result<Option<(AccountHeader, AccountStorageHeader)>, DatabaseError> {
        crate::db::queries::select_account_header_with_storage_header_at_block(
            self.inner, account_id, block_num,
        )
    }
}
