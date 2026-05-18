//! Account-related queries and models.

use diesel::prelude::*;
use miden_node_db::DatabaseError;
use miden_node_proto::domain::account::NetworkAccountId;
use miden_protocol::account::Account;

use crate::db::models::conv as conversions;
use crate::db::schema;

// MODELS
// ================================================================================================

/// Row for inserting into the `accounts` table.
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = schema::accounts)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct AccountInsert {
    pub account_id: Vec<u8>,
    pub account_data: Vec<u8>,
}

/// Row read from `accounts`.
#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = schema::accounts)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct AccountRow {
    pub account_data: Vec<u8>,
}

// QUERIES
// ================================================================================================

/// Inserts or replaces the account state.
///
/// # Raw SQL
///
/// ```sql
/// INSERT OR REPLACE INTO accounts (account_id, account_data) VALUES (?1, ?2)
/// ```
pub fn upsert_account(
    conn: &mut SqliteConnection,
    account_id: NetworkAccountId,
    account: &Account,
) -> Result<(), DatabaseError> {
    let row = AccountInsert {
        account_id: conversions::network_account_id_to_bytes(account_id),
        account_data: conversions::account_to_bytes(account),
    };
    diesel::replace_into(schema::accounts::table).values(&row).execute(conn)?;
    Ok(())
}

/// Returns the account state, or `None` if no row exists.
///
/// # Raw SQL
///
/// ```sql
/// SELECT account_data FROM accounts WHERE account_id = ?1 LIMIT 1
/// ```
pub fn get_account(
    conn: &mut SqliteConnection,
    account_id: NetworkAccountId,
) -> Result<Option<Account>, DatabaseError> {
    let account_id_bytes = conversions::network_account_id_to_bytes(account_id);

    let row: Option<AccountRow> = schema::accounts::table
        .filter(schema::accounts::account_id.eq(&account_id_bytes))
        .select(AccountRow::as_select())
        .first(conn)
        .optional()?;

    row.map(|AccountRow { account_data, .. }| conversions::account_from_bytes(&account_data))
        .transpose()
}
