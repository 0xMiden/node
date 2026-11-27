use miden_protocol::account::{AccountHeader, AccountId, AccountStorageHeader};

use super::ReadTransaction;
use crate::{DatabaseError, ScopedBlockNum};

impl ReadTransaction<'_> {
    /// Checks that account history at the requested block remains available.
    pub fn check_account_history_target(&self, block: ScopedBlockNum) -> Result<(), DatabaseError> {
        crate::db::queries::check_account_history_target(self.inner, *block)
    }

    /// Loads the public account and storage headers at a retained height.
    pub fn account_headers(
        &self,
        account: AccountId,
        block: ScopedBlockNum,
    ) -> Result<(AccountHeader, AccountStorageHeader), DatabaseError> {
        crate::db::queries::account_headers(self.inner, account, block)
    }
}

impl ReadTransaction<'_> {
    /// Looks up the header pair used to validate a witness request at a tree-scoped height.
    pub fn select_account_headers(
        &self,
        account: AccountId,
        block: ScopedBlockNum,
    ) -> Result<Option<(AccountHeader, AccountStorageHeader)>, DatabaseError> {
        crate::db::queries::select_account_header_with_storage_header_at_block(
            self.inner, account, *block,
        )
    }
}
