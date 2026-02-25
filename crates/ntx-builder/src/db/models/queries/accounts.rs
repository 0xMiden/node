//! Account-related queries and models.

use diesel::dsl::exists;
use diesel::prelude::*;
use miden_node_db::DatabaseError;
use miden_node_proto::domain::account::NetworkAccountId;
use miden_protocol::account::Account;
use miden_protocol::transaction::TransactionId;

use crate::db::models::conv as conversions;
use crate::db::schema;

// MODELS
// ================================================================================================

/// Row for inserting into the unified `accounts` table.
///
/// `transaction_id = None` means committed; `Some(tx_id_bytes)` means inflight.
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = schema::accounts)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct AccountInsert {
    pub account_id: Vec<u8>,
    pub account_data: Vec<u8>,
    pub transaction_id: Option<Vec<u8>>,
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

/// Inserts or replaces the committed account state (`transaction_id = NULL`).
///
/// Deletes any existing committed row first, then inserts a fresh one.
///
/// # Raw SQL
///
/// ```sql
/// DELETE FROM accounts WHERE account_id = ?1 AND transaction_id IS NULL
///
/// INSERT INTO accounts (account_id, account_data, transaction_id)
/// VALUES (?1, ?2, NULL)
/// ```
pub fn upsert_committed_account(
    conn: &mut SqliteConnection,
    account_id: NetworkAccountId,
    account: &Account,
) -> Result<(), DatabaseError> {
    let account_id_bytes = conversions::network_account_id_to_bytes(account_id);

    // Delete the existing committed row (if any).
    diesel::delete(
        schema::accounts::table
            .filter(schema::accounts::account_id.eq(&account_id_bytes))
            .filter(schema::accounts::transaction_id.is_null()),
    )
    .execute(conn)?;

    // Insert the new committed row.
    let row = AccountInsert {
        account_id: account_id_bytes,
        account_data: conversions::account_to_bytes(account),
        transaction_id: None,
    };
    diesel::insert_into(schema::accounts::table).values(&row).execute(conn)?;
    Ok(())
}

/// Returns the latest account state: last inflight row (highest `order_id`), or committed if
/// none.
///
/// # Raw SQL
///
/// ```sql
/// SELECT account_data
/// FROM accounts
/// WHERE account_id = ?1
/// ORDER BY order_id DESC
/// LIMIT 1
/// ```
pub fn get_account(
    conn: &mut SqliteConnection,
    account_id: NetworkAccountId,
) -> Result<Option<Account>, DatabaseError> {
    let account_id_bytes = conversions::network_account_id_to_bytes(account_id);

    // ORDER BY order_id DESC returns the latest inflight first, then committed.
    let row: Option<AccountRow> = schema::accounts::table
        .filter(schema::accounts::account_id.eq(&account_id_bytes))
        .order(schema::accounts::order_id.desc())
        .select(AccountRow::as_select())
        .first(conn)
        .optional()?;

    row.map(|AccountRow { account_data, .. }| conversions::account_from_bytes(&account_data))
        .transpose()
}

/// Returns `true` when an inflight account row exists with the given `transaction_id`.
///
/// # Raw SQL
///
/// ```sql
/// SELECT EXISTS (SELECT 1 FROM accounts WHERE transaction_id = ?1)
/// ```
pub fn transaction_exists(
    conn: &mut SqliteConnection,
    tx_id: &TransactionId,
) -> Result<bool, DatabaseError> {
    let tx_id_bytes = conversions::transaction_id_to_bytes(tx_id);

    let result: bool = diesel::select(exists(
        schema::accounts::table.filter(schema::accounts::transaction_id.eq(&tx_id_bytes)),
    ))
    .get_result(conn)?;

    Ok(result)
}
