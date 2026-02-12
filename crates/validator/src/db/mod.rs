mod migrations;
mod models;
mod schema;

use std::collections::HashSet;
use std::path::PathBuf;

use diesel::SqliteConnection;
use diesel::prelude::*;
use miden_node_store::{ConnectionManager, DatabaseError, DatabaseSetupError};
use miden_protocol::transaction::TransactionId;
use miden_protocol::utils::{Deserializable, Serializable};
use tracing::instrument;

use crate::COMPONENT;
use crate::db::migrations::apply_migrations;
use crate::db::models::ValidatedTransactionRowInsert;
use crate::tx_validation::ValidatedTransaction;

/// Open a connection to the DB and apply any pending migrations.
#[instrument(target = COMPONENT, skip_all)]
pub async fn load(database_filepath: PathBuf) -> Result<miden_node_store::Db, DatabaseSetupError> {
    let manager = ConnectionManager::new(database_filepath.to_str().unwrap());
    let pool = deadpool_diesel::Pool::builder(manager).max_size(16).build()?;

    tracing::info!(
        target: COMPONENT,
        sqlite= %database_filepath.display(),
        "Connected to the database"
    );

    let db = miden_node_store::Db::new(pool);
    db.query("migrations", apply_migrations).await?;
    db.query("configure_connection", configure_connection).await?;
    Ok(db)
}

/// Inserts a new validated transaction into the database.
#[instrument(target = COMPONENT, skip_all, fields(tx_id = %tx_info.tx_id()), err)]
pub(crate) fn insert_transaction(
    conn: &mut SqliteConnection,
    tx_info: &ValidatedTransaction,
) -> Result<usize, DatabaseError> {
    let row = ValidatedTransactionRowInsert::new(tx_info);
    let count = diesel::insert_into(schema::validated_transactions::table)
        .values(row)
        .on_conflict_do_nothing()
        .execute(conn)?;
    Ok(count)
}

/// Scans the database for transaction Ids that do not exist.
///
/// If the resulting vector is empty, all supplied transaction ids have been validated in the past.
///
/// # Raw SQL
///
/// ```sql
/// SELECT
///     id
/// FROM
///     validated_transactions
/// WHERE
///     id IN (?, ...)
/// ORDER BY
///     id ASC
/// ```
#[instrument(target = COMPONENT, skip(conn), err)]
pub(crate) fn find_unvalidated_transactions(
    conn: &mut SqliteConnection,
    tx_ids: &[TransactionId],
) -> Result<Vec<TransactionId>, DatabaseError> {
    if tx_ids.is_empty() {
        return Ok(Vec::new());
    }

    // Convert TransactionIds to bytes for query.
    let tx_id_bytes: Vec<Vec<u8>> = tx_ids.iter().map(TransactionId::to_bytes).collect();

    // Query the database for matching transactions ids.
    let raw_transaction_ids = schema::validated_transactions::table
        .select(schema::validated_transactions::id)
        .filter(schema::validated_transactions::id.eq_any(tx_id_bytes))
        .order(schema::validated_transactions::id.asc())
        .load::<Vec<u8>>(conn)
        .map_err(DatabaseError::from)?;

    // Find any requested ids that the database does not contain.
    let validated_tx_ids = raw_transaction_ids
        .into_iter()
        .map(|raw_id| TransactionId::read_from_bytes(&raw_id))
        .collect::<Result<HashSet<TransactionId>, _>>()?;
    let mut unvalidated_tx_ids = Vec::new();
    for tx_id in tx_ids {
        if !validated_tx_ids.contains(tx_id) {
            unvalidated_tx_ids.push(*tx_id);
        }
    }
    Ok(unvalidated_tx_ids)
}

pub(crate) fn configure_connection(conn: &mut SqliteConnection) -> Result<(), DatabaseError> {
    // Enable the WAL mode. This allows concurrent reads while a write is in progress.
    diesel::sql_query("PRAGMA journal_mode=WAL").execute(conn)?;

    // Wait up to 5 seconds for writer locks before erroring.
    diesel::sql_query("PRAGMA busy_timeout=5000").execute(conn)?;

    // Enable foreign key checks.
    diesel::sql_query("PRAGMA foreign_keys=ON").execute(conn)?;
    Ok(())
}
