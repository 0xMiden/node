mod migrations;
mod models;
mod schema;

use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use diesel::SqliteConnection;
use diesel::dsl::{count_star, exists};
use diesel::prelude::*;
use miden_node_db::{DatabaseError, Db, SqlTypeConvert};
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::transaction::TransactionId;
use miden_protocol::utils::serde::{Deserializable, Serializable};
use tracing::instrument;

use crate::db::migrations::{bootstrap_database, migrate_database, verify_latest_schema};
use crate::db::models::{BlockHeaderRowInsert, ValidatedTransactionRowInsert};
use crate::tx_validation::ValidatedTransaction;
use crate::{COMPONENT, LOG_TARGET};

/// Open a connection to the DB after verifying that it is at the latest schema version.
#[instrument(target = COMPONENT, skip_all)]
pub async fn load(database_filepath: PathBuf) -> Result<Db, DatabaseError> {
    load_with_pool_size(database_filepath, miden_node_db::default_connection_pool_size()).await
}

/// Open a connection to the DB with a specific pool size after verifying that it is at the latest
/// schema version.
#[instrument(target = COMPONENT, skip_all)]
pub async fn load_with_pool_size(
    database_filepath: PathBuf,
    connection_pool_size: NonZeroUsize,
) -> Result<Db, DatabaseError> {
    verify_latest_schema(&database_filepath)?;

    open_with_pool_size(&database_filepath, connection_pool_size)
}

/// Creates a new database, applies all migrations, and opens a connection pool.
#[instrument(target = COMPONENT, skip_all)]
pub async fn setup(database_filepath: PathBuf) -> Result<Db, DatabaseError> {
    setup_with_pool_size(database_filepath, miden_node_db::default_connection_pool_size()).await
}

/// Creates a new database with a specific pool size and applies all migrations.
#[instrument(target = COMPONENT, skip_all)]
pub async fn setup_with_pool_size(
    database_filepath: PathBuf,
    connection_pool_size: NonZeroUsize,
) -> Result<Db, DatabaseError> {
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
) -> Result<Db, DatabaseError> {
    let db = Db::new_with_pool_size(database_filepath, connection_pool_size)?;
    tracing::info!(
        target: LOG_TARGET,
        sqlite= %database_filepath.display(),
        connection_pool_size = %connection_pool_size,
        "Connected to the database"
    );
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

/// Returns whether a transaction with the given id has already been validated.
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
pub(crate) fn transaction_exists(
    conn: &mut SqliteConnection,
    tx_id: TransactionId,
) -> Result<bool, DatabaseError> {
    let exists = diesel::select(exists(
        schema::validated_transactions::table
            .filter(schema::validated_transactions::id.eq(tx_id.to_bytes())),
    ))
    .get_result::<bool>(conn)?;
    Ok(exists)
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

/// Upserts a block header into the database.
///
/// Inserts a new row if no block header exists at the given block number, or replaces the
/// existing block header if one already exists.
#[instrument(target = COMPONENT, skip(conn, header), err)]
pub fn upsert_block_header(
    conn: &mut SqliteConnection,
    header: &BlockHeader,
) -> Result<(), DatabaseError> {
    let row = BlockHeaderRowInsert {
        block_num: header.block_num().to_raw_sql(),
        block_header: header.to_bytes(),
    };
    diesel::replace_into(schema::block_headers::table).values(row).execute(conn)?;
    Ok(())
}

/// Loads the chain tip (block header with the highest block number) from the database.
///
/// Returns `None` if no block headers have been persisted (i.e. bootstrap has not been run).
#[instrument(target = COMPONENT, skip(conn), err)]
pub fn load_chain_tip(conn: &mut SqliteConnection) -> Result<Option<BlockHeader>, DatabaseError> {
    let row = schema::block_headers::table
        .order(schema::block_headers::block_num.desc())
        .select(schema::block_headers::block_header)
        .first::<Vec<u8>>(conn)
        .optional()?;

    row.map(|bytes| {
        BlockHeader::read_from_bytes(&bytes)
            .map_err(|err| DatabaseError::deserialization("BlockHeader", err))
    })
    .transpose()
}

/// Loads a block header by its block number.
///
/// Returns `None` if no block header exists at the given block number.
#[instrument(target = COMPONENT, skip(conn), err)]
pub fn load_block_header(
    conn: &mut SqliteConnection,
    block_num: BlockNumber,
) -> Result<Option<BlockHeader>, DatabaseError> {
    let row = schema::block_headers::table
        .filter(schema::block_headers::block_num.eq(block_num.to_raw_sql()))
        .select(schema::block_headers::block_header)
        .first::<Vec<u8>>(conn)
        .optional()?;

    row.map(|bytes| {
        BlockHeader::read_from_bytes(&bytes)
            .map_err(|err| DatabaseError::deserialization("BlockHeader", err))
    })
    .transpose()
}

/// Returns the total number of validated transactions in the database.
#[instrument(target = COMPONENT, skip(conn), err)]
pub fn count_validated_transactions(conn: &mut SqliteConnection) -> Result<i64, DatabaseError> {
    let count = schema::validated_transactions::table.select(count_star()).first::<i64>(conn)?;
    Ok(count)
}

/// Returns the total number of signed blocks in the database.
#[instrument(target = COMPONENT, skip(conn), err)]
pub fn count_signed_blocks(conn: &mut SqliteConnection) -> Result<i64, DatabaseError> {
    let count = schema::block_headers::table.select(count_star()).first::<i64>(conn)?;
    Ok(count)
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

    #[tokio::test]
    async fn transaction_exists_detects_validated_transactions() {
        use miden_protocol::Word;

        let temp_dir = tempfile::tempdir().expect("failed to create temp directory");
        let db = setup(temp_dir.path().join("validator.sqlite3")).await.unwrap();

        let validated_id = TransactionId::from_raw(Word::try_from([1u64, 2, 3, 4]).unwrap());
        let unknown_id = TransactionId::from_raw(Word::try_from([5u64, 6, 7, 8]).unwrap());

        // Insert a row keyed by `validated_id`. Only the primary key matters for this query, so the
        // remaining columns are filled with placeholder bytes.
        let row = ValidatedTransactionRowInsert {
            id: validated_id.to_bytes(),
            block_num: 0,
            account_id: vec![],
            account_delta: vec![],
            input_notes: vec![],
            output_notes: vec![],
            initial_account_hash: vec![],
            final_account_hash: vec![],
            fee: vec![],
        };
        db.transact("insert_row", move |conn| -> Result<usize, DatabaseError> {
            Ok(diesel::insert_into(schema::validated_transactions::table)
                .values(row)
                .execute(conn)?)
        })
        .await
        .unwrap();

        let validated_exists = db
            .query("transaction_exists", move |conn| transaction_exists(conn, validated_id))
            .await
            .unwrap();
        assert!(validated_exists, "an inserted transaction id should be reported as existing");

        let unknown_exists = db
            .query("transaction_exists", move |conn| transaction_exists(conn, unknown_id))
            .await
            .unwrap();
        assert!(!unknown_exists, "an unknown transaction id should not be reported as existing");
    }
}
