use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use miden_node_db::DatabaseError;
use miden_node_db::sqlite::{DbReader, DbWriter};
use miden_node_tracing::{info, miden_instrument};
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::transaction::TransactionId;

use crate::db::migrations::{bootstrap_database, migrate_database, verify_latest_schema};
use crate::metrics::InitialMetrics;
use crate::{COMPONENT, LOG_TARGET, StorageKeyEpoch, StoredPrivateRecord};

mod migrations;
mod queries;

pub(crate) use queries::{ListTransactionsParams, ListedTransaction};

// VALIDATOR DATABASE
// ================================================================================================

/// Read-only handle to the validator database.
///
/// Wraps the framework [`DbReader`] and exposes every read query as a method. Cloneable, and handed
/// to read-only components (the administration API); it has no write methods, so those components
/// cannot mutate the database.
#[derive(Clone)]
pub struct ValidatorDbReader {
    reader: DbReader,
}

impl ValidatorDbReader {
    /// Returns whether a transaction with the given id has already been validated.
    pub(crate) async fn transaction_exists(
        &self,
        tx_id: TransactionId,
    ) -> Result<bool, DatabaseError> {
        self.reader
            .read("transaction_exists", move |tx| queries::transaction_exists(tx, tx_id))
            .await
    }

    /// Returns the subset of `tx_ids` that this validator has not validated yet.
    ///
    /// An empty result means all supplied transaction ids have been validated in the past.
    pub(crate) async fn find_unvalidated_transactions(
        &self,
        tx_ids: Vec<TransactionId>,
    ) -> Result<Vec<TransactionId>, DatabaseError> {
        self.reader
            .read("find_unvalidated_transactions", move |tx| {
                queries::find_unvalidated_transactions(tx, &tx_ids)
            })
            .await
    }

    /// Loads the chain tip, or `None` if no block header has been persisted yet (i.e. bootstrap has
    /// not been run).
    #[miden_instrument(
        target = COMPONENT,
    )]
    pub(crate) async fn load_chain_tip(&self) -> Result<Option<BlockHeader>, DatabaseError> {
        self.reader.read("load_chain_tip", queries::load_chain_tip).await
    }

    /// Loads the block header at the given height, or `None` if no block header is stored there.
    pub(crate) async fn load_block_header(
        &self,
        block_num: BlockNumber,
    ) -> Result<Option<BlockHeader>, DatabaseError> {
        self.reader
            .read("load_block_header", move |tx| queries::load_block_header(tx, block_num))
            .await
    }

    /// Reads the values the server's in-memory counters start from, all within a single read
    /// transaction so that they describe one consistent database state.
    pub(crate) async fn load_initial_metrics(&self) -> Result<InitialMetrics, DatabaseError> {
        self.reader
            .read("load_initial_metrics", |tx| {
                Ok(InitialMetrics {
                    chain_tip: queries::load_chain_tip(tx)?
                        .map_or(0, |header| header.block_num().as_u32()),
                    validated_transactions: u64::try_from(queries::count_validated_transactions(
                        tx,
                    )?)
                    .unwrap_or(0),
                    signed_blocks: u64::try_from(queries::count_signed_blocks(tx)?).unwrap_or(0),
                })
            })
            .await
    }

    /// Returns the total number of validated transactions.
    ///
    /// Production code seeds its counter from [`Self::load_initial_metrics`] and tracks it in
    /// memory from there, so this standalone count only backs test assertions about what was
    /// actually persisted.
    #[cfg(test)]
    pub(crate) async fn count_validated_transactions(&self) -> Result<i64, DatabaseError> {
        self.reader
            .read("count_validated_transactions", queries::count_validated_transactions)
            .await
    }

    /// Loads one encrypted private record by transaction id.
    pub async fn load_private_record(
        &self,
        transaction_id: TransactionId,
    ) -> Result<Option<StoredPrivateRecord>, DatabaseError> {
        self.reader
            .read("load_private_record", move |tx| {
                queries::load_private_record(tx, transaction_id)
            })
            .await
    }

    /// Loads the encrypted private records sealed under one storage key epoch.
    pub async fn load_private_records_by_key_epoch(
        &self,
        key_epoch: StorageKeyEpoch,
    ) -> Result<Vec<StoredPrivateRecord>, DatabaseError> {
        self.reader
            .read("load_private_records_by_key_epoch", move |tx| {
                queries::load_private_records_by_key_epoch(tx, key_epoch)
            })
            .await
    }

    /// Loads the encrypted private records belonging to one Golden setup context.
    pub async fn load_private_records_by_setup_context(
        &self,
        setup_context_id: [u8; 32],
    ) -> Result<Vec<StoredPrivateRecord>, DatabaseError> {
        self.reader
            .read("load_private_records_by_setup_context", move |tx| {
                queries::load_private_records_by_setup_context(tx, setup_context_id)
            })
            .await
    }

    /// Loads one page of committed transactions in chronological order i.e. `(block_num,
    /// block_tx_index)`.
    pub(crate) async fn list_validated_transactions(
        &self,
        params: queries::ListTransactionsParams,
    ) -> Result<Vec<queries::ListedTransaction>, DatabaseError> {
        self.reader
            .read("list_validated_transactions", move |tx| {
                queries::list_validated_transactions(tx, &params)
            })
            .await
    }
}

/// Write handle to the validator database.
///
/// Wraps the framework [`DbWriter`] and additionally holds a [`ValidatorDbReader`], so it exposes
/// the write queries directly and every read query through `Deref`. **Not `Clone`**: writes have a
/// single owner, matching SQLite's single-writer model.
pub struct ValidatorDbWriter {
    writer: DbWriter,
    reader: ValidatorDbReader,
}

impl std::ops::Deref for ValidatorDbWriter {
    type Target = ValidatorDbReader;

    fn deref(&self) -> &Self::Target {
        &self.reader
    }
}

impl ValidatorDbWriter {
    /// Returns a read-only handle onto the same connection pool, for handing to components that
    /// must not be able to write.
    pub fn reader(&self) -> ValidatorDbReader {
        self.reader.clone()
    }

    /// Inserts a validated transaction and its encrypted private inputs, returning the number of
    /// inserted rows. The count is zero if the transaction was already recorded.
    #[miden_instrument(
        target = COMPONENT,
    )]
    pub async fn insert_validated_private_transaction(
        &self,
        record: StoredPrivateRecord,
    ) -> Result<usize, DatabaseError> {
        self.writer
            .write("insert_validated_private_transaction", move |tx| {
                queries::insert_validated_private_transaction(tx, &record)
            })
            .await
    }

    /// Persists a block header, replacing any header already stored at the same height.
    #[miden_instrument(
        target = COMPONENT,
    )]
    pub(crate) async fn upsert_block_header(
        &self,
        header: BlockHeader,
    ) -> Result<(), DatabaseError> {
        self.writer
            .write("upsert_block_header", move |tx| queries::upsert_block_header(tx, &header))
            .await
    }

    /// Persists a signed block's header and links the block's transactions to their in-block
    /// positions, all in one database transaction so the header and the links stay consistent.
    ///
    /// The height must not already hold a block; use [`Self::replace_signed_block`] to replace
    /// one.
    #[miden_instrument(
        target = COMPONENT,
    )]
    pub(crate) async fn insert_signed_block(
        &self,
        header: BlockHeader,
        transactions: Vec<TransactionId>,
    ) -> Result<(), DatabaseError> {
        self.writer
            .write("insert_signed_block", move |tx| {
                persist_signed_block(tx, &header, &transactions)
            })
            .await
    }

    /// Replaces the block signed at `header`'s height, in one database transaction: deletes the
    /// replaced block — unlinking its transactions via the `ON DELETE CASCADE` on
    /// `block_transactions`, so transactions dropped by the replacement do not keep a stale link —
    /// then persists the new header and links exactly as [`Self::insert_signed_block`] does.
    #[miden_instrument(
        target = COMPONENT,
    )]
    pub(crate) async fn replace_signed_block(
        &self,
        header: BlockHeader,
        transactions: Vec<TransactionId>,
    ) -> Result<(), DatabaseError> {
        self.writer
            .write("replace_signed_block", move |tx| {
                queries::delete_block(tx, header.block_num())?;
                persist_signed_block(tx, &header, &transactions)
            })
            .await
    }
}

/// Persists a signed block's header and links its transactions, within the caller's database
/// transaction: the shared tail of [`ValidatorDbWriter::insert_signed_block`] and
/// [`ValidatorDbWriter::replace_signed_block`].
fn persist_signed_block(
    tx: &miden_node_db::sqlite::WriteTx<'_>,
    header: &BlockHeader,
    transactions: &[TransactionId],
) -> Result<(), DatabaseError> {
    queries::insert_block_header(tx, header)?;
    queries::link_block_transactions(tx, header.block_num(), transactions)
}

// LIFECYCLE
// ================================================================================================

/// Opens a connection pool after verifying that the database is at the latest schema version.
#[miden_instrument(
    target = COMPONENT,
)]
pub async fn load(database_filepath: PathBuf) -> Result<ValidatorDbWriter, DatabaseError> {
    load_with_pool_size(database_filepath, miden_node_db::default_connection_pool_size()).await
}

/// Opens a connection pool with a specific pool size after verifying that the database is at the
/// latest schema version.
#[miden_instrument(
    target = COMPONENT,
)]
pub async fn load_with_pool_size(
    database_filepath: PathBuf,
    connection_pool_size: NonZeroUsize,
) -> Result<ValidatorDbWriter, DatabaseError> {
    verify_latest_schema(&database_filepath)?;

    open_with_pool_size(&database_filepath, connection_pool_size)
}

/// Creates a new database, applies all migrations, and opens a connection pool.
#[miden_instrument(
    target = COMPONENT,
)]
pub async fn setup(database_filepath: PathBuf) -> Result<ValidatorDbWriter, DatabaseError> {
    setup_with_pool_size(database_filepath, miden_node_db::default_connection_pool_size()).await
}

/// Creates a new database with a specific pool size and applies all migrations.
#[miden_instrument(
    target = COMPONENT,
)]
async fn setup_with_pool_size(
    database_filepath: PathBuf,
    connection_pool_size: NonZeroUsize,
) -> Result<ValidatorDbWriter, DatabaseError> {
    bootstrap_database(&database_filepath)?;

    open_with_pool_size(&database_filepath, connection_pool_size)
}

/// Creates and initializes the database, then seeds it with the genesis block header as the chain
/// tip.
///
/// Returns an error if the database has already been bootstrapped.
#[miden_instrument(
    target = COMPONENT,
    fields(path = database_filepath),
    err,
)]
pub async fn bootstrap(
    database_filepath: PathBuf,
    connection_pool_size: NonZeroUsize,
    genesis_header: BlockHeader,
) -> Result<(), DatabaseError> {
    let db = setup_with_pool_size(database_filepath, connection_pool_size).await?;

    db.upsert_block_header(genesis_header).await
}

/// Applies all pending migrations to an existing DB.
#[miden_instrument(
    target = COMPONENT,
)]
pub fn migrate(database_filepath: impl AsRef<Path>) -> Result<(), DatabaseError> {
    migrate_database(database_filepath.as_ref())?;
    Ok(())
}

fn open_with_pool_size(
    database_filepath: &Path,
    connection_pool_size: NonZeroUsize,
) -> Result<ValidatorDbWriter, DatabaseError> {
    let (writer, reader) =
        miden_node_db::sqlite::open_with_pool_size(database_filepath, connection_pool_size)?;
    info!(
        target: LOG_TARGET,
        "Connected to the database",
        path = database_filepath,
        db.sqlite.connection_pool_size = connection_pool_size.get()
    );
    Ok(ValidatorDbWriter {
        writer,
        reader: ValidatorDbReader { reader },
    })
}

#[cfg(test)]
mod tests {
    use miden_protocol::Word;
    use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey;
    use miden_protocol::utils::serde::Deserializable;
    use rand_chacha_03::ChaCha20Rng;
    use rand_chacha_03::rand_core::SeedableRng;

    use super::*;
    use crate::private_record::test_private_record_sealer;
    use crate::storage_key::tests::operator_keys;
    use crate::{
        PrivateRecordChainId,
        PrivateRecordCombiner,
        PrivateRecordContext,
        PrivateRecordId,
        PrivateRecordSealer,
        PrivateRecordShareRequest,
    };

    const CHAIN_ID: PrivateRecordChainId = PrivateRecordChainId::new([1; 32]);
    const KEY_EPOCH: StorageKeyEpoch = StorageKeyEpoch::new([2; 32]);
    const SETUP_CONTEXT_ID: [u8; 32] = [4; 32];

    fn record_id(transaction_id: TransactionId) -> PrivateRecordId {
        let signer = SigningKey::read_from_bytes(&[7; 32]).unwrap();
        PrivateRecordId::new(transaction_id, &signer.public_key())
    }

    fn private_record(transaction_id: TransactionId, seed: u8) -> StoredPrivateRecord {
        let context = PrivateRecordContext::new(CHAIN_ID, KEY_EPOCH, transaction_id);
        let mut rng = ChaCha20Rng::from_seed([seed; 32]);
        test_private_record_sealer(KEY_EPOCH, SETUP_CONTEXT_ID)
            .seal(&mut rng, record_id(transaction_id), context, b"private transaction inputs")
            .unwrap()
    }

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
        let temp_dir = tempfile::tempdir().expect("failed to create temp directory");
        let db = setup(temp_dir.path().join("validator.sqlite3")).await.unwrap();

        let validated_id = TransactionId::from_raw(Word::try_from([1u64, 2, 3, 4]).unwrap());
        let unknown_id = TransactionId::from_raw(Word::try_from([5u64, 6, 7, 8]).unwrap());

        db.insert_validated_private_transaction(private_record(validated_id, 1))
            .await
            .unwrap();

        assert!(
            db.transaction_exists(validated_id).await.unwrap(),
            "an inserted transaction id should be reported as existing"
        );
        assert!(
            !db.transaction_exists(unknown_id).await.unwrap(),
            "an unknown transaction id should not be reported as existing"
        );
    }

    /// The `rarray`-based lookup must return exactly the ids that are absent, preserving the order
    /// they were supplied in.
    #[tokio::test]
    async fn find_unvalidated_transactions_returns_only_missing_ids() {
        let temp_dir = tempfile::tempdir().expect("failed to create temp directory");
        let db = setup(temp_dir.path().join("validator.sqlite3")).await.unwrap();

        let ids = (1u64..=4)
            .map(|i| TransactionId::from_raw(Word::try_from([i, i, i, i]).unwrap()))
            .collect::<Vec<_>>();

        // Validate the second and fourth ids only.
        db.insert_validated_private_transaction(private_record(ids[1], 1))
            .await
            .unwrap();
        db.insert_validated_private_transaction(private_record(ids[3], 2))
            .await
            .unwrap();

        let unvalidated = db.find_unvalidated_transactions(ids.clone()).await.unwrap();
        assert_eq!(unvalidated, vec![ids[0], ids[2]]);

        // An empty request must not error and must return nothing.
        assert!(db.find_unvalidated_transactions(vec![]).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn load_initial_metrics_reports_persisted_state() {
        let temp_dir = tempfile::tempdir().expect("failed to create temp directory");
        let db = setup(temp_dir.path().join("validator.sqlite3")).await.unwrap();

        // A freshly bootstrapped database is empty.
        let metrics = db.load_initial_metrics().await.unwrap();
        assert_eq!(metrics.chain_tip, 0);
        assert_eq!(metrics.validated_transactions, 0);
        assert_eq!(metrics.signed_blocks, 0);
    }

    #[tokio::test]
    async fn private_record_indexes_work() {
        let temp_dir = tempfile::tempdir().expect("failed to create temp directory");
        let db = setup(temp_dir.path().join("validator.sqlite3")).await.unwrap();
        let transaction_id = TransactionId::from_raw(Word::from([5u32, 6, 7, 8]));
        let record = private_record(transaction_id, 9);

        let expected = record.clone();
        db.insert_validated_private_transaction(record).await.unwrap();

        let by_record = db.load_private_record(transaction_id).await.unwrap();
        assert_eq!(by_record, Some(expected.clone()));

        let by_epoch = db.load_private_records_by_key_epoch(KEY_EPOCH).await.unwrap();
        assert_eq!(by_epoch, vec![expected.clone()]);

        let by_setup = db.load_private_records_by_setup_context(SETUP_CONTEXT_ID).await.unwrap();
        assert_eq!(by_setup, vec![expected.clone()]);
    }

    /// Validated transactions that are not part of a signed block have no position in the committed
    /// order, so the listing does not surface them at all.
    #[tokio::test]
    async fn uncommitted_transactions_are_not_listed() {
        let temp_dir = tempfile::tempdir().expect("failed to create temp directory");
        let db = setup(temp_dir.path().join("validator.sqlite3")).await.unwrap();
        let transaction_ids = [
            TransactionId::from_raw(Word::from([9u32, 0, 0, 0])),
            TransactionId::from_raw(Word::from([1u32, 0, 0, 0])),
        ];
        for (transaction_id, seed) in transaction_ids.into_iter().zip([1u8, 2]) {
            db.insert_validated_private_transaction(private_record(transaction_id, seed))
                .await
                .unwrap();
        }

        let params = ListTransactionsParams { start: None, block_to: None, limit: 10 };
        assert!(db.list_validated_transactions(params).await.unwrap().is_empty());
        // They remain reachable by transaction id.
        assert!(db.load_private_record(transaction_ids[0]).await.unwrap().is_some());
    }

    /// A signed block links its transactions in block order; replacing the block at the same height
    /// deletes the replaced block's links along with its header.
    #[tokio::test]
    async fn insert_signed_block_links_and_relinks_transactions() {
        let temp_dir = tempfile::tempdir().expect("failed to create temp directory");
        let db = setup(temp_dir.path().join("validator.sqlite3")).await.unwrap();
        let transaction_ids = (1u64..=3)
            .map(|i| TransactionId::from_raw(Word::try_from([i, i, i, i]).unwrap()))
            .collect::<Vec<_>>();
        for (seed, transaction_id) in [1u8, 2, 3].into_iter().zip(&transaction_ids) {
            db.insert_validated_private_transaction(private_record(*transaction_id, seed))
                .await
                .unwrap();
        }

        let header = BlockHeader::mock(7, None, None, &[], Word::empty());
        db.insert_signed_block(header.clone(), vec![transaction_ids[0], transaction_ids[1]])
            .await
            .unwrap();

        let params = ListTransactionsParams { start: None, block_to: None, limit: 10 };
        let listed = db.list_validated_transactions(params).await.unwrap();
        assert_eq!(
            listed
                .iter()
                .map(|item| (item.transaction_id, item.block_num, item.block_tx_index))
                .collect::<Vec<_>>(),
            vec![
                (transaction_ids[0], BlockNumber::from(7u32), 0),
                (transaction_ids[1], BlockNumber::from(7u32), 1),
            ],
        );

        // Replace the block at the same height with one that only includes the third transaction.
        // The two transactions the replacement drops go back to being uncommitted, and stop being
        // listed.
        db.replace_signed_block(header, vec![transaction_ids[2]]).await.unwrap();

        let listed = db.list_validated_transactions(params).await.unwrap();
        assert_eq!(
            listed
                .iter()
                .map(|item| (item.transaction_id, item.block_num, item.block_tx_index))
                .collect::<Vec<_>>(),
            vec![(transaction_ids[2], BlockNumber::from(7u32), 0)],
        );
    }

    /// A full sweep pages through committed transactions in committed order, honoring the row limit
    /// exactly, with each page resuming one position past the last row of the previous one.
    #[tokio::test]
    async fn list_validated_transactions_pages_in_committed_order() {
        let temp_dir = tempfile::tempdir().expect("failed to create temp directory");
        let db = setup(temp_dir.path().join("validator.sqlite3")).await.unwrap();
        let transaction_ids = (1u64..=5)
            .map(|i| TransactionId::from_raw(Word::try_from([i, i, i, i]).unwrap()))
            .collect::<Vec<_>>();
        for (seed, transaction_id) in (1u8..=5).zip(&transaction_ids) {
            db.insert_validated_private_transaction(private_record(*transaction_id, seed))
                .await
                .unwrap();
        }
        // Blocks 1 and 2 include two transactions each; the fifth is never committed. The later
        // insertion is committed in the earlier block, to prove the listing follows committed order
        // rather than insertion order.
        let block_1 = BlockHeader::mock(1, None, None, &[], Word::empty());
        let block_2 = BlockHeader::mock(2, None, None, &[], Word::empty());
        db.insert_signed_block(block_1, vec![transaction_ids[3], transaction_ids[0]])
            .await
            .unwrap();
        db.insert_signed_block(block_2, vec![transaction_ids[1], transaction_ids[2]])
            .await
            .unwrap();
        let expected_order =
            [transaction_ids[3], transaction_ids[0], transaction_ids[1], transaction_ids[2]];

        // Sweep with a limit of three: the first page ends mid-block, and the next page resumes one
        // position past the last row returned.
        let mut swept = Vec::new();
        let mut start = None;
        loop {
            let params = ListTransactionsParams { start, block_to: None, limit: 3 };
            let page = db.list_validated_transactions(params).await.unwrap();
            let Some(last) = page.last() else { break };
            assert!(page.len() <= 3, "a page must honor the row limit");
            start = Some((last.block_num, last.block_tx_index + 1));
            swept.extend(page.into_iter().map(|item| item.transaction_id));
        }
        assert_eq!(swept, expected_order);

        // Bounding by block number: `start` excludes block 1, `block_to` excludes block 2.
        let from_block_2 = db
            .list_validated_transactions(ListTransactionsParams {
                start: Some((BlockNumber::from(2u32), 0)),
                block_to: None,
                limit: 10,
            })
            .await
            .unwrap();
        assert_eq!(
            from_block_2.iter().map(|item| item.transaction_id).collect::<Vec<_>>(),
            vec![transaction_ids[1], transaction_ids[2]],
        );
        let up_to_block_1 = db
            .list_validated_transactions(ListTransactionsParams {
                start: None,
                block_to: Some(BlockNumber::from(1u32)),
                limit: 10,
            })
            .await
            .unwrap();
        assert_eq!(
            up_to_block_1.iter().map(|item| item.transaction_id).collect::<Vec<_>>(),
            vec![transaction_ids[3], transaction_ids[0]],
        );
    }

    /// Linking a transaction this validator never validated fails the foreign key on
    /// `block_transactions`, so a signed block cannot silently reference unknown transactions.
    #[tokio::test]
    async fn insert_signed_block_rejects_unvalidated_transactions() {
        let temp_dir = tempfile::tempdir().expect("failed to create temp directory");
        let db = setup(temp_dir.path().join("validator.sqlite3")).await.unwrap();
        let header = BlockHeader::mock(1, None, None, &[], Word::empty());
        let unknown = TransactionId::from_raw(Word::from([1u32, 0, 0, 0]));

        let result = db.insert_signed_block(header, vec![unknown]).await;
        assert!(result.is_err(), "linking an unvalidated transaction must fail");
    }

    #[tokio::test]
    async fn stored_private_record_opens_with_threshold_shares() {
        let temp_dir = tempfile::tempdir().expect("failed to create temp directory");
        let db = setup(temp_dir.path().join("validator.sqlite3")).await.unwrap();
        let operators = operator_keys();
        let transaction_id = TransactionId::from_raw(Word::from([9u32, 10, 11, 12]));
        let context = PrivateRecordContext::new(CHAIN_ID, operators[0].key_epoch(), transaction_id);
        let plaintext = b"private transaction inputs";
        let mut seal_rng = ChaCha20Rng::from_seed([40; 32]);
        let record = PrivateRecordSealer::from_operator_key(&operators[0])
            .seal(&mut seal_rng, record_id(transaction_id), context, plaintext)
            .unwrap();
        db.insert_validated_private_transaction(record).await.unwrap();

        let stored = db.load_private_record(transaction_id).await.unwrap().unwrap();
        let request = PrivateRecordShareRequest::for_record(&stored);
        let mut first_rng = ChaCha20Rng::from_seed([41; 32]);
        let mut second_rng = ChaCha20Rng::from_seed([42; 32]);
        let shares = [
            operators[0]
                .issue_private_record_share(&mut first_rng, &request, &stored)
                .unwrap(),
            operators[1]
                .issue_private_record_share(&mut second_rng, &request, &stored)
                .unwrap(),
        ];

        let opened = PrivateRecordCombiner::from_operator_key(&operators[2])
            .unwrap()
            .open(&request, &stored, &shares)
            .unwrap();
        assert_eq!(opened.as_slice(), plaintext);
    }

    #[tokio::test]
    async fn private_record_schema_has_required_indexes() {
        let temp_dir = tempfile::tempdir().expect("failed to create temp directory");
        let db = setup(temp_dir.path().join("validator.sqlite3")).await.unwrap();

        let schema = db
            .reader
            .reader
            .read("private_record_schema", |tx| {
                tx.query(
                    "SELECT sql FROM sqlite_schema \
                     WHERE tbl_name IN ('validated_transactions', 'block_transactions') \
                       AND sql IS NOT NULL \
                     ORDER BY name",
                    &[],
                    |row| row.get::<String>(0),
                )
            })
            .await
            .unwrap()
            .join("\n");

        assert!(schema.contains("insertion_sequence    INTEGER PRIMARY KEY AUTOINCREMENT"));
        assert!(schema.contains("id                    BLOB NOT NULL UNIQUE"));
        assert!(schema.contains("idx_validated_transactions_key_epoch"));
        assert!(schema.contains("idx_validated_transactions_setup_context_id"));
        assert!(schema.contains("PRIMARY KEY (block_num, block_tx_index)"));
    }
}
