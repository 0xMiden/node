use miden_protocol::account::{AccountId, AccountStorageHeader, StorageSlotName, StorageSlotType};

use crate::{GetAccountError, ScopedBlockNum};

/// A request for a missing slot or a value slot is a client error. The forest has no map root for
/// such a slot, so a forest lookup cannot tell this case apart from a missing storage root.
pub fn validate_storage_map_slots<'a>(
    account_id: AccountId,
    block_num: ScopedBlockNum,
    slots: impl IntoIterator<Item = &'a StorageSlotName>,
    storage_header: &AccountStorageHeader,
) -> Result<(), GetAccountError> {
    for slot_name in slots {
        let slot = storage_header.find_slot_header_by_name(slot_name).ok_or_else(|| {
            GetAccountError::StorageSlotNotFound {
                account_id,
                slot_name: slot_name.clone(),
                block_num: *block_num,
            }
        })?;
        if slot.slot_type() != StorageSlotType::Map {
            return Err(GetAccountError::StorageSlotNotMap {
                account_id,
                slot_name: slot_name.clone(),
                block_num: *block_num,
            });
        }
    }
    Ok(())
}
