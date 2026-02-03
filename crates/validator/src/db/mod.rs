mod migrations;
mod models;
mod schema;

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use diesel::SqliteConnection;
use diesel::prelude::*;
use miden_node_store::{ConnectionManager, DatabaseError, DatabaseSetupError};
use miden_protocol::transaction::{TransactionId, TransactionSummary};
use miden_protocol::utils::{Deserializable, Serializable};
use tracing::instrument;

use crate::COMPONENT;
use crate::db::migrations::apply_migrations;
use crate::db::models::{TransactionSummaryRowInsert, TransactionSummaryRowSelect};

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
    Ok(db)
}

/// Inserts a new validated transaction into the database.
pub(crate) fn insert_transaction(
    conn: &mut SqliteConnection,
    tx_id: &TransactionId,
    summary: &TransactionSummary,
) -> Result<usize, DatabaseError> {
    let row = TransactionSummaryRowInsert::new(tx_id, summary);
    let count = diesel::insert_into(schema::transactions::table).values(row).execute(conn)?;
    Ok(count)
}

/// Retrieves validated transactions from the database.
#[allow(dead_code)]
pub(crate) fn select_validated_transactions(
    conn: &mut SqliteConnection,
    tx_ids: &[TransactionId],
) -> Result<HashMap<TransactionId, TransactionSummary>, DatabaseError> {
    if tx_ids.is_empty() {
        return Ok(HashMap::new());
    }

    // Convert TransactionIds to bytes for query.
    let tx_id_bytes: Vec<Vec<u8>> = tx_ids.iter().map(TransactionId::to_bytes).collect();

    // Query the database for matching transactions.
    let raw_transactions = schema::transactions::table
        .filter(schema::transactions::id.eq_any(tx_id_bytes))
        .order(schema::transactions::id.asc())
        .load::<TransactionSummaryRowSelect>(conn)
        .map_err(DatabaseError::from)?;

    // Deserialize the transaction blobs.
    let mut transactions: HashMap<TransactionId, TransactionSummary> = HashMap::new();
    for raw_tx in raw_transactions {
        let id = TransactionId::read_from_bytes(&raw_tx.id)?;
        let summary = TransactionSummary::read_from_bytes(&raw_tx.summary)?;
        transactions.insert(id, summary);
    }

    Ok(transactions)
}

/// Scans the database for transaction Ids that do not exist.
///
/// If the resulting vector is empty, all supplied transaction ids have been validated in the past.
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
    let raw_transactions_ids = schema::transactions::table
        .select(schema::transactions::id)
        .filter(schema::transactions::id.eq_any(tx_id_bytes))
        .order(schema::transactions::id.asc())
        .load::<Vec<u8>>(conn)
        .map_err(DatabaseError::from)?;

    // Find any requested ids that the database does not contain.
    let expected_tx_ids = tx_ids.iter().copied().collect::<HashSet<TransactionId>>();
    let mut unvalidated_tx_ids = Vec::new();
    for raw_tx_id in raw_transactions_ids {
        let tx_id = TransactionId::read_from_bytes(&raw_tx_id)?;
        if !expected_tx_ids.contains(&tx_id) {
            unvalidated_tx_ids.push(tx_id);
        }
    }
    Ok(unvalidated_tx_ids)
}
