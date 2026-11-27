use miden_node_db::sqlite::{ReadTx, WriteTx};
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;

use crate::errors::DatabaseError;

/// Counts of live public account state, independent of RPC limits and retained history length.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AccountSize {
    pub storage_slots: u64,
    pub storage_map_entries: u64,
    pub vault_assets: u64,
}

impl AccountSize {
    pub fn total(self) -> u64 {
        self.storage_slots
            .saturating_add(self.storage_map_entries)
            .saturating_add(self.vault_assets)
    }
}

pub(crate) fn select_account_size(
    tx: &ReadTx<'_>,
    account: AccountId,
    block: BlockNumber,
) -> Result<Option<AccountSize>, DatabaseError> {
    Ok(tx
        .query(include_str!("select_account_size.sql"), &[&account, &block], |row| {
            let count = |column| {
                u64::try_from(row.get::<i64>(column)?).map_err(|err| {
                    miden_node_db::DatabaseError::deserialization("account size", err)
                })
            };
            Ok(AccountSize {
                storage_slots: count(0)?,
                storage_map_entries: count(1)?,
                vault_assets: count(2)?,
            })
        })?
        .into_iter()
        .next())
}

pub(crate) fn update_account_size(
    tx: &WriteTx<'_>,
    account: AccountId,
    block: BlockNumber,
    size: AccountSize,
) -> Result<(), DatabaseError> {
    let sql_count = |count| {
        i64::try_from(count).map_err(|_| {
            DatabaseError::DataCorrupted("account size exceeds SQLite integer range".into())
        })
    };
    tx.execute(
        include_str!("update_account_size.sql"),
        &[
            &account,
            &block,
            &sql_count(size.storage_slots)?,
            &sql_count(size.storage_map_entries)?,
            &sql_count(size.vault_assets)?,
        ],
    )?;
    Ok(())
}
