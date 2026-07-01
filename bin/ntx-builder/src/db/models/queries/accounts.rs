//! Account-related queries and models.

use diesel::prelude::*;
use miden_node_db::DatabaseError;
use miden_protocol::account::{Account, AccountId};
use miden_protocol::transaction::TransactionId;

use crate::db::models::conv as conversions;
use crate::db::schema;

// MODELS
// ================================================================================================

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = schema::accounts)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct AccountInsert {
    pub account_id: Vec<u8>,
    pub account_data: Vec<u8>,
    pub last_tx_id: Vec<u8>,
}

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = schema::accounts)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct AccountRow {
    pub account_data: Vec<u8>,
}

// QUERIES
// ================================================================================================

/// Inserts the committed account state, or updates an existing account's state. In both cases
/// `last_tx_id` is set to the transaction that produced this update.
///
/// # Raw SQL
///
/// ```sql
/// INSERT INTO accounts (account_id, account_data, last_tx_id)
/// VALUES (?1, ?2, ?3)
/// ON CONFLICT(account_id) DO UPDATE SET
///     account_data = excluded.account_data,
///     last_tx_id = excluded.last_tx_id
/// ```
pub fn upsert_account(
    conn: &mut SqliteConnection,
    account_id: AccountId,
    account: &Account,
    last_tx_id: TransactionId,
) -> Result<(), DatabaseError> {
    let row = AccountInsert {
        account_id: conversions::account_id_to_bytes(account_id),
        account_data: conversions::account_to_bytes(account),
        last_tx_id: conversions::transaction_id_to_bytes(&last_tx_id),
    };
    diesel::insert_into(schema::accounts::table)
        .values(&row)
        .on_conflict(schema::accounts::account_id)
        .do_update()
        .set((
            schema::accounts::account_data.eq(&row.account_data),
            schema::accounts::last_tx_id.eq(&row.last_tx_id),
        ))
        .execute(conn)?;
    Ok(())
}

/// Returns the latest transaction recorded against `account_id`, or `None` if the account is not
/// tracked locally.
///
/// The committed-transaction landing check now reads `last_committed_tx` from the
/// [`AccountView`](crate::coordinator) the coordinator pushes, so this read accessor is only used by
/// tests to verify that `upsert_account` persists `accounts.last_tx_id` correctly.
///
/// # Raw SQL
///
/// ```sql
/// SELECT last_tx_id FROM accounts WHERE account_id = ?1
/// ```
#[cfg(test)]
pub fn account_last_tx(
    conn: &mut SqliteConnection,
    account_id: AccountId,
) -> Result<Option<TransactionId>, DatabaseError> {
    let account_id_bytes = conversions::account_id_to_bytes(account_id);

    let last_tx_id: Option<Vec<u8>> = schema::accounts::table
        .find(&account_id_bytes)
        .select(schema::accounts::last_tx_id)
        .first(conn)
        .optional()?;

    last_tx_id
        .map(|bytes| conversions::transaction_id_from_bytes(&bytes))
        .transpose()
}

/// Returns `true` if a committed state for the given account is tracked locally.
///
/// # Raw SQL
///
/// ```sql
/// SELECT EXISTS (SELECT 1 FROM accounts WHERE account_id = ?1)
/// ```
pub fn account_exists(
    conn: &mut SqliteConnection,
    account_id: AccountId,
) -> Result<bool, DatabaseError> {
    let account_id_bytes = conversions::account_id_to_bytes(account_id);

    let exists =
        diesel::select(diesel::dsl::exists(schema::accounts::table.find(&account_id_bytes)))
            .get_result(conn)?;

    Ok(exists)
}

/// Returns the committed account state for the given network account.
///
/// # Raw SQL
///
/// ```sql
/// SELECT account_data FROM accounts WHERE account_id = ?1
/// ```
pub fn get_account(
    conn: &mut SqliteConnection,
    account_id: AccountId,
) -> Result<Option<Account>, DatabaseError> {
    let account_id_bytes = conversions::account_id_to_bytes(account_id);

    let row: Option<AccountRow> = schema::accounts::table
        .find(&account_id_bytes)
        .select(AccountRow::as_select())
        .first(conn)
        .optional()?;

    row.map(|AccountRow { account_data }| conversions::account_from_bytes(&account_data))
        .transpose()
}
