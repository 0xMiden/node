use std::num::NonZeroUsize;

use miden_protocol::account::AccountId;

use super::ReadTransaction;
use crate::{AccountVaultCursor, AccountVaultValuesPage, DatabaseError, ScopedBlockRange};

impl ReadTransaction<'_> {
    /// Reads a bounded page of squashed account vault updates.
    pub fn account_vault_updates_page(
        &self,
        account: AccountId,
        range: ScopedBlockRange,
        cursor: Option<&AccountVaultCursor>,
        page_size: NonZeroUsize,
    ) -> Result<AccountVaultValuesPage, DatabaseError> {
        crate::db::queries::account_vault_updates_page(
            self.inner, account, range, cursor, page_size,
        )
    }
}
