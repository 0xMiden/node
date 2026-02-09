//! Account-related queries and models.

use diesel::prelude::*;
use miden_node_proto::domain::account::NetworkAccountId;
use miden_protocol::account::Account;

use crate::db::errors::DatabaseError;
use crate::db::models::conv as conversions;
use crate::db::schema;

// MODELS
// ================================================================================================

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = schema::committed_accounts)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct CommittedAccountInsert {
    pub account_id: Vec<u8>,
    pub account_data: Vec<u8>,
}

/// Row read from `inflight_account_deltas`.
///
/// Only includes columns we need; use `.select(InflightDeltaRow::as_select())` when querying.
#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = schema::inflight_account_deltas)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct InflightDeltaRow {
    pub id: Option<i32>,
    pub account_id: Vec<u8>,
    pub account_data: Vec<u8>,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = schema::inflight_account_deltas)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct InflightDeltaInsert {
    pub account_id: Vec<u8>,
    pub transaction_id: Vec<u8>,
    pub account_data: Vec<u8>,
}

// QUERIES
// ================================================================================================

/// Inserts or replaces a committed account.
pub fn upsert_committed_account(
    conn: &mut SqliteConnection,
    account: &Account,
) -> Result<(), DatabaseError> {
    let row = CommittedAccountInsert {
        account_id: conversions::account_id_to_bytes(account.id()),
        account_data: conversions::account_to_bytes(account),
    };
    diesel::replace_into(schema::committed_accounts::table)
        .values(&row)
        .execute(conn)?;
    Ok(())
}

/// Returns the latest account state: tries inflight deltas first, falls back to committed.
/// (Design doc 3.1)
pub fn latest_account(
    conn: &mut SqliteConnection,
    account_id: NetworkAccountId,
) -> Result<Option<Account>, DatabaseError> {
    let account_id_bytes = conversions::network_account_id_to_bytes(account_id);

    // Try inflight_account_deltas (ORDER BY id DESC LIMIT 1).
    let inflight: Option<InflightDeltaRow> = schema::inflight_account_deltas::table
        .filter(schema::inflight_account_deltas::account_id.eq(&account_id_bytes))
        .order(schema::inflight_account_deltas::id.desc())
        .select(InflightDeltaRow::as_select())
        .first(conn)
        .optional()?;

    if let Some(row) = inflight {
        return Ok(Some(conversions::account_from_bytes(&row.account_data)?));
    }

    // Fallback to committed_accounts.
    let committed: Option<Vec<u8>> = schema::committed_accounts::table
        .find(&account_id_bytes)
        .select(schema::committed_accounts::account_data)
        .first(conn)
        .optional()?;

    match committed {
        Some(bytes) => Ok(Some(conversions::account_from_bytes(&bytes)?)),
        None => Ok(None),
    }
}
