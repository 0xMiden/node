use miden_node_db::Transaction;
use miden_protocol::account::{AccountStorageHeader, StorageSlotType};

/// Adds size counters to historical public-account rows, leaving private-account counters null.
///
/// Header decoding identifies live map slots, so removed slots and tombstones do not contribute
/// to the backfilled counts.
pub fn migrate(tx: &Transaction<'_>) -> anyhow::Result<()> {
    tx.execute_batch(include_str!("009_account_sizes/add_columns.sql"))?;
    let mut accounts = tx.prepare(include_str!("009_account_sizes/select_public_accounts.sql"))?;
    let mut rows = accounts.query([])?;
    while let Some(row) = rows.next()? {
        let account: Vec<u8> = row.get(0)?;
        let block: i64 = row.get(1)?;
        let header: Vec<u8> = row.get(2)?;
        let header = miden_node_persistence::decode::<AccountStorageHeader>(&header)?;
        let mut entries = 0_i64;
        for slot in header.slots().filter(|slot| slot.slot_type() == StorageSlotType::Map) {
            entries += tx.query_row(
                include_str!("009_account_sizes/count_storage_map_entries.sql"),
                (&account, slot.name().as_str(), block),
                |row| row.get::<_, i64>(0),
            )?;
        }
        let assets: i64 = tx.query_row(
            include_str!("009_account_sizes/count_vault_assets.sql"),
            (&account, block),
            |row| row.get(0),
        )?;
        tx.execute(
            include_str!("009_account_sizes/update_account_size.sql"),
            (&account, block, i64::try_from(header.slots().count())?, entries, assets),
        )?;
    }
    Ok(())
}
