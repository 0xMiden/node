//! Database query functions for the store, on the `miden-node-db` SQLite framework.
//!
//! Each function takes a [`ReadTx`](miden_node_db::sqlite::ReadTx) or
//! [`WriteTx`](miden_node_db::sqlite::WriteTx) and is driven from a [`Db`](crate::db::Db) method
//! through [`DbReader::read`](miden_node_db::sqlite::DbReader::read) /
//! [`DbWriter::write`](miden_node_db::sqlite::DbWriter::write). One module per query, holding the
//! function and the `.sql` file it executes.
//!
//! The store is being migrated to the framework incrementally: every write goes through the
//! modules here, while most reads still run on the diesel layer in [`crate::db::models`]. Read
//! queries move here one batch at a time until the diesel layer is removed.

use miden_node_db::DatabaseError;
use miden_node_db::sqlite::{DbValue, DbValueRef, FromSqlValue, ToSqlValue};

// SHARED COLUMN TYPES
// =================================================================================================

/// Sentinel `valid_until` value marking a row as the current, open-ended version of its key.
///
/// Versioned rows (`accounts`, `account_vault_assets`, `account_storage_map_values`) are
/// applicable for blocks in `[block_num, valid_until)`; updating a key closes the previous row's
/// interval by setting its `valid_until` to the new row's `block_num`. The open end is `i64::MAX`
/// rather than NULL so every validity predicate is a single range comparison that partial indexes
/// can serve.
pub(crate) const VALID_FOREVER: i64 = i64::MAX;

/// Classifies accounts for database storage based on whether they are network accounts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
pub(crate) enum NetworkAccountType {
    /// Not a network account.
    None = 0,
    /// A network account.
    Network = 1,
}

impl ToSqlValue for NetworkAccountType {
    fn to_sql_value(&self) -> DbValue {
        DbValue::integer(*self as i64)
    }
}

impl FromSqlValue for NetworkAccountType {
    fn from_sql_value(value: DbValueRef<'_>) -> Result<Self, DatabaseError> {
        match value.as_i64()? {
            0 => Ok(Self::None),
            1 => Ok(Self::Network),
            other => Err(DatabaseError::deserialization(
                "NetworkAccountType",
                InvalidNetworkAccountType(other),
            )),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid network account type value {0}")]
struct InvalidNetworkAccountType(i64);

// BLOCK QUERIES
// =================================================================================================

mod insert_block_header;
pub(crate) use insert_block_header::insert_block_header;

// PROTOCOL CONFIG QUERIES
// =================================================================================================

mod insert_protocol_config;
pub(crate) use insert_protocol_config::insert_protocol_config;

// NOTE QUERIES
// =================================================================================================

mod insert_note_scripts;
pub(crate) use insert_note_scripts::insert_note_scripts;

mod insert_notes;
pub(crate) use insert_notes::insert_notes;

// NULLIFIER QUERIES
// =================================================================================================

mod insert_nullifiers_for_block;
pub(crate) use insert_nullifiers_for_block::insert_nullifiers_for_block;

// TRANSACTION QUERIES
// =================================================================================================

mod insert_transactions;
pub(crate) use insert_transactions::insert_transactions;

// ACCOUNT QUERIES
// =================================================================================================

mod insert_storage_map_value;
pub(crate) use insert_storage_map_value::insert_storage_map_value;

mod insert_vault_asset;
pub(crate) use insert_vault_asset::insert_vault_asset;

mod prune_history;
pub use prune_history::HISTORICAL_BLOCK_RETENTION;
pub(crate) use prune_history::prune_history;

mod upsert_accounts;
pub(crate) use upsert_accounts::{AccountRow, upsert_accounts};
pub use upsert_accounts::{PrecomputedPublicAccountState, PrecomputedPublicAccountStates};

mod filter_network_accounts;
pub(crate) use filter_network_accounts::filter_network_accounts;

mod select_account_header_with_storage_header_at_block;
pub(crate) use select_account_header_with_storage_header_at_block::select_account_header_with_storage_header_at_block;

mod select_vault_at_block;
pub(crate) use select_vault_at_block::select_vault_at_block;

#[cfg(test)]
mod select_full_account;
#[cfg(test)]
pub(crate) use select_full_account::select_full_account;

#[cfg(test)]
mod select_latest_storage;
#[cfg(test)]
pub(crate) use select_latest_storage::select_latest_storage;

// BLOCK APPLICATION
// =================================================================================================

mod apply_block;
pub(crate) use apply_block::apply_block;
