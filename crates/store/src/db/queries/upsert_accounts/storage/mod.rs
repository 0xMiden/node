use miden_node_db::sqlite::WriteTx;
use miden_protocol::account::{AccountUpdateDetails, StoragePatchOperation, StorageSlotType};
use miden_protocol::block::BlockAccountUpdate;

use super::{AccountRow, LatestAccountStateRow};
use crate::db::queries::VALID_FOREVER;
use crate::errors::DatabaseError;

/// Sets `valid_until` to the current block for entries in removed or recreated storage maps,
/// returning the number of nonzero entries expired.
///
/// The entries remain available for historical queries. Expiring them before inserting new
/// entries prevents recreated maps from inheriting their previous contents.
pub(super) fn expire_removed_map_entries(
    tx: &WriteTx<'_>,
    update: &BlockAccountUpdate,
    existing: &LatestAccountStateRow,
    row: &AccountRow,
) -> Result<i64, DatabaseError> {
    let Some(header) = &row.storage_header else {
        return Ok(0);
    };
    let account = row.account_id;
    let mut removed = 0;
    let old_header = existing.state_headers(account)?.storage_header;
    for slot in old_header.slots().filter(|slot| slot.slot_type() == StorageSlotType::Map) {
        let retained = header
            .slots()
            .any(|new| new.name() == slot.name() && new.slot_type() == StorageSlotType::Map);
        let recreated = match update.details() {
            AccountUpdateDetails::Public(patch) => patch.storage().maps().any(|(name, patch)| {
                name == slot.name() && patch.patch_op() == StoragePatchOperation::Create
            }),
            AccountUpdateDetails::Private => false,
        };
        if retained && !recreated {
            continue;
        }
        let count = tx.query(
            include_str!("count_storage_map_entries.sql"),
            &[&account, slot.name(), &VALID_FOREVER],
            |row| row.get::<i64>(0),
        )?[0];
        removed += count;
        tx.execute(
            include_str!("close_storage_map_entries.sql"),
            &[&row.block_num, &account, slot.name(), &VALID_FOREVER],
        )?;
    }

    Ok(removed)
}
