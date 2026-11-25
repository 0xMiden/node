use std::num::NonZeroUsize;

use miden_protocol::account::AccountId;

use super::ReadTransaction;
use crate::{DatabaseError, ScopedBlockRange, StorageMapCursor, StorageMapUpdatesPage};

impl ReadTransaction<'_> {
    /// Reads a bounded page of squashed account storage map updates.
    pub fn account_storage_map_updates_page(
        &self,
        account: AccountId,
        range: ScopedBlockRange,
        cursor: Option<&StorageMapCursor>,
        page_size: NonZeroUsize,
    ) -> Result<StorageMapUpdatesPage, DatabaseError> {
        crate::db::queries::account_storage_map_updates_page(
            self.inner, account, range, cursor, page_size,
        )
    }
}
