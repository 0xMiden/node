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
}

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = schema::accounts)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct AccountRow {
    pub account_data: Vec<u8>,
}

// QUERIES
// ================================================================================================

/// Inserts the committed account state, or updates `account_data` if the account already exists.
///
/// # Raw SQL
///
/// ```sql
/// INSERT INTO accounts (account_id, account_data)
/// VALUES (?1, ?2)
/// ON CONFLICT(account_id) DO UPDATE SET account_data = excluded.account_data
/// ```
pub fn upsert_account(
    conn: &mut SqliteConnection,
    account_id: AccountId,
    account: &Account,
) -> Result<(), DatabaseError> {
    let row = AccountInsert {
        account_id: conversions::account_id_to_bytes(account_id),
        account_data: conversions::account_to_bytes(account),
    };
    diesel::insert_into(schema::accounts::table)
        .values(&row)
        .on_conflict(schema::accounts::account_id)
        .do_update()
        .set(schema::accounts::account_data.eq(&row.account_data))
        .execute(conn)?;
    Ok(())
}

/// Records `tx_id` as the latest transaction that updated `account_id`. No-ops for accounts not
/// tracked locally (i.e. non-network accounts), which never have a row in this table.
///
/// # Raw SQL
///
/// ```sql
/// UPDATE accounts SET last_tx_id = ?2 WHERE account_id = ?1
/// ```
pub fn set_account_last_tx(
    conn: &mut SqliteConnection,
    account_id: AccountId,
    tx_id: TransactionId,
) -> Result<(), DatabaseError> {
    let account_id_bytes = conversions::account_id_to_bytes(account_id);
    let tx_id_bytes = conversions::transaction_id_to_bytes(&tx_id);
    diesel::update(schema::accounts::table.find(&account_id_bytes))
        .set(schema::accounts::last_tx_id.eq(Some(tx_id_bytes)))
        .execute(conn)?;
    Ok(())
}

/// Returns the latest transaction recorded against `account_id`, if any.
///
/// # Raw SQL
///
/// ```sql
/// SELECT last_tx_id FROM accounts WHERE account_id = ?1
/// ```
pub fn account_last_tx(
    conn: &mut SqliteConnection,
    account_id: AccountId,
) -> Result<Option<TransactionId>, DatabaseError> {
    let account_id_bytes = conversions::account_id_to_bytes(account_id);

    let last_tx_id: Option<Option<Vec<u8>>> = schema::accounts::table
        .find(&account_id_bytes)
        .select(schema::accounts::last_tx_id)
        .first(conn)
        .optional()?;

    last_tx_id
        .flatten()
        .map(|bytes| conversions::transaction_id_from_bytes(&bytes))
        .transpose()
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
