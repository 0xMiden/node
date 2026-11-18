use std::collections::BTreeMap;

use miden_node_proto::domain::account::{AccountStorageMapDetails, StorageMapEntries};
use miden_protocol::account::{AccountId, StorageMapKey, StorageSlotName};
use miden_protocol::block::BlockNumber;
use miden_protocol::{EMPTY_WORD, Word};

use super::ReadTransaction;
use crate::DatabaseError;
use crate::db::pagination::Paginated;
use crate::db::queries::AccountStorageMapValuesPaged;

impl ReadTransaction<'_> {
    /// Reconstructs the entries of a storage map slot as of `block_num` from its stored history.
    ///
    /// Returns [`StorageMapEntries::LimitExceeded`] when the map holds more than
    /// [`AccountStorageMapDetails::MAX_RETURN_ENTRIES`] entries, or when a single block wrote more
    /// values than fit in one page of `page_limit` values.
    pub(crate) fn select_storage_map(
        &self,
        account_id: AccountId,
        slot_name: StorageSlotName,
        block_num: BlockNumber,
        page_limit: usize,
    ) -> Result<AccountStorageMapDetails, DatabaseError> {
        // TODO this remains expensive with a large history until we implement pruning for DB
        // columns
        let query = AccountStorageMapValuesPaged::new(account_id, block_num, page_limit);
        let mut latest_values = BTreeMap::<StorageMapKey, Word>::new();
        let mut next = Some(BlockNumber::GENESIS);
        while let Some(cursor) = next {
            let page = match query.page(self.inner, &cursor) {
                Ok(page) => page,
                // A single block holds more entries than fit in a page, as with genesis accounts
                // that have large storage maps.
                Err(DatabaseError::BlockExceedsPageLimit { .. }) => {
                    return Ok(AccountStorageMapDetails::limit_exceeded(slot_name));
                },
                Err(err) => return Err(err),
            };
            // Pages are in block order, so later values replace earlier ones.
            for value in page.items {
                if value.slot_name == slot_name {
                    latest_values.insert(value.key, value.value);
                }
            }
            next = page.next;
        }

        // Remove EMPTY_WORD entries (deletions)
        latest_values.retain(|_, v| *v != EMPTY_WORD);

        if latest_values.len() > AccountStorageMapDetails::MAX_RETURN_ENTRIES {
            return Ok(AccountStorageMapDetails::limit_exceeded(slot_name));
        }

        Ok(AccountStorageMapDetails {
            slot_name,
            entries: StorageMapEntries::AllEntries(latest_values.into_iter().collect()),
        })
    }
}
