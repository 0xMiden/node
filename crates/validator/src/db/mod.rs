mod migrations;
mod models;
mod schema;

use std::collections::HashMap;
use std::path::PathBuf;

use diesel::SqliteConnection;
use diesel::prelude::*;
use miden_node_store::{ConnectionManager, DatabaseError, DatabaseSetupError};
use miden_protocol::transaction::{TransactionHeader, TransactionId};
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

pub(crate) fn insert_transaction(
    conn: &mut SqliteConnection,
    header: &TransactionHeader,
) -> Result<usize, DatabaseError> {
    let row = TransactionSummaryRowInsert::new(header);
    let count = diesel::insert_into(schema::transactions::table).values(row).execute(conn)?;
    Ok(count)
}

pub(crate) fn select_validated_transactions(
    conn: &mut SqliteConnection,
    tx_ids: &[TransactionId],
) -> Result<HashMap<TransactionId, TransactionHeader>, DatabaseError> {
    if tx_ids.is_empty() {
        return Ok(HashMap::new());
    }

    // Convert TransactionIds to bytes for query.
    let tx_id_bytes: Vec<Vec<u8>> = tx_ids.iter().map(TransactionId::to_bytes).collect();

    // Query the database for matching transactions.
    let raw_transactions = schema::transactions::table
        .filter(schema::transactions::transaction_id.eq_any(tx_id_bytes))
        .order(schema::transactions::transaction_id.asc())
        .load::<TransactionSummaryRowSelect>(conn)
        .map_err(DatabaseError::from)?;

    // Deserialize the transaction blobs.
    let mut transactions: HashMap<TransactionId, TransactionHeader> = HashMap::new();
    for raw_tx in raw_transactions {
        let tx_id = TransactionId::read_from_bytes(&raw_tx.transaction_id)?;
        let tx_header = TransactionHeader::read_from_bytes(&raw_tx.data)?;
        transactions.insert(tx_id, tx_header);
    }

    Ok(transactions)
}
