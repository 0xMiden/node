mod migrations;
mod models;
mod schema;

use std::path::PathBuf;

use diesel::SqliteConnection;
use diesel::dsl::exists;
use diesel::prelude::*;
use miden_node_db::{ConnectionManager, DatabaseError, DatabaseSetupError};
use miden_protocol::transaction::TransactionId;
use miden_protocol::utils::Serializable;
use tracing::instrument;

use crate::COMPONENT;
use crate::db::migrations::apply_migrations;
use crate::db::models::ValidatedTransactionRowInsert;
use crate::tx_validation::ValidatedTransaction;

/// Open a connection to the DB and apply any pending migrations.
#[instrument(target = COMPONENT, skip_all)]
pub async fn load(database_filepath: PathBuf) -> Result<miden_node_db::Db, DatabaseSetupError> {
    let manager = ConnectionManager::new(database_filepath.to_str().unwrap());
    let pool = deadpool_diesel::Pool::builder(manager).max_size(16).build()?;

    tracing::info!(
        target: COMPONENT,
        sqlite= %database_filepath.display(),
        "Connected to the database"
    );

    let db = miden_node_db::Db::new(pool);
    db.query("migrations", apply_migrations).await?;
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
/// SELECT EXISTS(
///   SELECT 1
///   FROM validated_transactions
///   WHERE id = ?
/// );
/// ```
#[instrument(target = COMPONENT, skip(conn), err)]
pub(crate) fn find_unvalidated_transactions(
    conn: &mut SqliteConnection,
    tx_ids: &[TransactionId],
) -> Result<Vec<TransactionId>, DatabaseError> {
    let mut unvalidated_tx_ids = Vec::new();
    for tx_id in tx_ids {
        // Check whether each transaction id exists in the database.
        let exists = diesel::select(exists(
            schema::validated_transactions::table
                .filter(schema::validated_transactions::id.eq(tx_id.to_bytes())),
        ))
        .get_result::<bool>(conn)?;
        // Record any transaction ids that do not exist.
        if !exists {
            unvalidated_tx_ids.push(*tx_id);
        }
    }
    Ok(unvalidated_tx_ids)
}
