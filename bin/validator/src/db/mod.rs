mod migrations;

use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use miden_node_db::DatabaseError;
use miden_node_db::sqlite::{Database, ReadTx, WriteTx};
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::transaction::TransactionId;
use miden_protocol::utils::serde::Serializable;
use tracing::instrument;

use crate::COMPONENT;
use crate::db::migrations::{bootstrap_database, migrate_database, verify_latest_schema};
use crate::tx_validation::ValidatedTransaction;

/// Open a connection to the DB after verifying that it is at the latest schema version.
#[instrument(target = COMPONENT, skip_all)]
pub async fn load(database_filepath: PathBuf) -> Result<Database, DatabaseError> {
    load_with_pool_size(database_filepath, miden_node_db::default_connection_pool_size()).await
}

/// Open a connection to the DB with a specific pool size after verifying that it is at the latest
/// schema version.
#[instrument(target = COMPONENT, skip_all)]
pub async fn load_with_pool_size(
    database_filepath: PathBuf,
    connection_pool_size: NonZeroUsize,
) -> Result<Database, DatabaseError> {
    verify_latest_schema(&database_filepath)?;

    open_with_pool_size(&database_filepath, connection_pool_size)
}

/// Creates a new database, applies all migrations, and opens a connection pool.
#[instrument(target = COMPONENT, skip_all)]
pub async fn setup(database_filepath: PathBuf) -> Result<Database, DatabaseError> {
    setup_with_pool_size(database_filepath, miden_node_db::default_connection_pool_size()).await
}

/// Creates a new database with a specific pool size and applies all migrations.
#[instrument(target = COMPONENT, skip_all)]
pub async fn setup_with_pool_size(
    database_filepath: PathBuf,
    connection_pool_size: NonZeroUsize,
) -> Result<Database, DatabaseError> {
    bootstrap_database(&database_filepath)?;

    open_with_pool_size(&database_filepath, connection_pool_size)
}

/// Applies all pending migrations to an existing DB.
#[instrument(target = COMPONENT, skip_all)]
pub fn migrate(database_filepath: impl AsRef<Path>) -> Result<(), DatabaseError> {
    migrate_database(database_filepath.as_ref())?;
    Ok(())
}

fn open_with_pool_size(
    database_filepath: &Path,
    connection_pool_size: NonZeroUsize,
) -> Result<Database, DatabaseError> {
    let db = Database::new_with_pool_size(database_filepath, connection_pool_size)?;
    tracing::info!(
        target: COMPONENT,
        sqlite= %database_filepath.display(),
        connection_pool_size = %connection_pool_size,
        "Connected to the database"
    );
    Ok(db)
}

/// Inserts a new validated transaction into the database.
#[instrument(target = COMPONENT, skip_all, fields(tx_id = %tx_info.tx_id()), err)]
pub(crate) fn insert_transaction(
    tx: &WriteTx<'_>,
    tx_info: &ValidatedTransaction,
) -> Result<usize, DatabaseError> {
    let id = tx_info.tx_id().to_bytes();
    let block_num = i64::from(tx_info.block_num().as_u32());
    let account_id = tx_info.account_id().to_bytes();
    let account_delta = tx_info.account_delta().to_bytes();
    let input_notes = tx_info.input_notes().to_bytes();
    let output_notes = tx_info.output_notes().to_bytes();
    let initial_account_hash = tx_info.initial_account_hash().to_bytes();
    let final_account_hash = tx_info.final_account_hash().to_bytes();
    let fee = tx_info.fee().amount().as_u64().to_le_bytes().to_vec();

    tx.execute(
        "INSERT INTO validated_transactions \
         (id, block_num, account_id, account_delta, input_notes, output_notes, \
          initial_account_hash, final_account_hash, fee) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) \
         ON CONFLICT DO NOTHING",
        &[
            &id,
            &block_num,
            &account_id,
            &account_delta,
            &input_notes,
            &output_notes,
            &initial_account_hash,
            &final_account_hash,
            &fee,
        ],
    )
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
#[instrument(target = COMPONENT, skip(tx), err)]
pub(crate) fn find_unvalidated_transactions(
    tx: &ReadTx<'_>,
    tx_ids: &[TransactionId],
) -> Result<Vec<TransactionId>, DatabaseError> {
    let mut unvalidated_tx_ids = Vec::new();
    for tx_id in tx_ids {
        // Check whether each transaction id exists in the database.
        let exists = tx.exists(
            "SELECT EXISTS(SELECT 1 FROM validated_transactions WHERE id = ?1)",
            &[&tx_id.to_bytes()],
        )?;
        // Record any transaction ids that do not exist.
        if !exists {
            unvalidated_tx_ids.push(*tx_id);
        }
    }
    Ok(unvalidated_tx_ids)
}

/// Upserts a block header into the database.
///
/// Inserts a new row if no block header exists at the given block number, or replaces the
/// existing block header if one already exists.
#[instrument(target = COMPONENT, skip(tx, header), err)]
pub fn upsert_block_header(tx: &WriteTx<'_>, header: &BlockHeader) -> Result<(), DatabaseError> {
    let block_num = i64::from(header.block_num().as_u32());
    let block_header = header.to_bytes();
    tx.execute(
        "REPLACE INTO block_headers (block_num, block_header) VALUES (?1, ?2)",
        &[&block_num, &block_header],
    )?;
    Ok(())
}

/// Loads the chain tip (block header with the highest block number) from the database.
///
/// Returns `None` if no block headers have been persisted (i.e. bootstrap has not been run).
#[instrument(target = COMPONENT, skip(tx), err)]
pub fn load_chain_tip(tx: &ReadTx<'_>) -> Result<Option<BlockHeader>, DatabaseError> {
    tx.query_opt(
        "SELECT block_header FROM block_headers ORDER BY block_num DESC LIMIT 1",
        &[],
        |row| row.get::<BlockHeader>(0),
    )
}

/// Loads a block header by its block number.
///
/// Returns `None` if no block header exists at the given block number.
#[instrument(target = COMPONENT, skip(tx), err)]
pub fn load_block_header(
    tx: &ReadTx<'_>,
    block_num: BlockNumber,
) -> Result<Option<BlockHeader>, DatabaseError> {
    tx.query_opt(
        "SELECT block_header FROM block_headers WHERE block_num = ?1",
        &[&i64::from(block_num.as_u32())],
        |row| row.get::<BlockHeader>(0),
    )
}

/// Returns the total number of validated transactions in the database.
#[instrument(target = COMPONENT, skip(tx), err)]
pub fn count_validated_transactions(tx: &ReadTx<'_>) -> Result<i64, DatabaseError> {
    tx.count("SELECT COUNT(*) FROM validated_transactions", &[])
}

/// Returns the total number of signed blocks in the database.
#[instrument(target = COMPONENT, skip(tx), err)]
pub fn count_signed_blocks(tx: &ReadTx<'_>) -> Result<i64, DatabaseError> {
    tx.count("SELECT COUNT(*) FROM block_headers", &[])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrate_rejects_missing_database() {
        let temp_dir = tempfile::tempdir().expect("failed to create temp directory");
        let db_path = temp_dir.path().join("validator.sqlite3");

        let err = migrate(db_path.clone()).expect_err("missing database should fail");

        assert!(matches!(err, DatabaseError::Migration(_)), "unexpected error: {err:?}");
        assert!(!db_path.exists());
    }

    #[tokio::test]
    async fn setup_creates_database_that_load_accepts() {
        let temp_dir = tempfile::tempdir().expect("failed to create temp directory");
        let db_path = temp_dir.path().join("validator.sqlite3");

        setup(db_path.clone()).await.expect("setup should bootstrap the database");
        load(db_path).await.expect("load should accept a bootstrapped database");
    }
}
