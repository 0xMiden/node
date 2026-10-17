use miden_node_db::Connection;

use super::*;
use crate::db::migrations::migrator;

/// Creates a schema-version-003 database and matching block files for migration 004.
fn database_at_version_003(directory: &Path) -> (PathBuf, SignedBlock, SignedBlock) {
    let path = directory.join("validator.sqlite3");
    migrator().unwrap().create_database(&path).unwrap().migrate_to(3).unwrap();
    let genesis = genesis_block(&test_protocol_config());
    let (_, body, signatures) = genesis.clone().into_parts();
    let header = protocol_config_history::header_at(genesis.header(), 1, &test_protocol_config());
    let next = SignedBlock::new_unchecked(header, body, signatures);
    let connection = Connection::open(&path).unwrap();
    fs_err::create_dir_all(directory.join("blocks/0000")).unwrap();
    fs_err::write(directory.join("blocks/format.pb"), [8, 1]).unwrap();
    for block in [&genesis, &next] {
        let height = block.header().block_num().as_u32();
        connection
            .execute(
                "INSERT INTO block_headers VALUES (?1, ?2)",
                (height, miden_node_persistence::encode(block.header())),
            )
            .unwrap();
        fs_err::write(
            directory.join(format!("blocks/0000/block_{height:08x}.dat")),
            miden_node_persistence::encode(block),
        )
        .unwrap();
    }
    (path, genesis, next)
}

#[tokio::test]
async fn migration_imports_committed_blocks_and_no_longer_needs_files() {
    let directory = tempfile::tempdir().unwrap();
    let (path, genesis, next) = database_at_version_003(directory.path());
    // An interrupted signing attempt can leave an uncommitted file beyond the database tip.
    fs_err::write(directory.path().join("blocks/0000/block_00000002.dat"), b"uncommitted").unwrap();
    migrator().unwrap().open_database(&path).unwrap().migrate_to(4).unwrap();
    for block in [&genesis, &next] {
        let height = block.header().block_num().as_u32();
        assert_eq!(
            fs_err::read(directory.path().join(format!("blocks/0000/block_{height:08x}.dat")))
                .unwrap(),
            miden_node_persistence::encode(block)
        );
    }
    fs_err::remove_dir_all(directory.path().join("blocks")).unwrap();
    migrator()
        .unwrap()
        .open_database(&path)
        .unwrap()
        .migrate_to(4)
        .expect("migration must be idempotent without legacy files");
    let db = open_with_pool_size(&path, NonZeroUsize::new(2).unwrap()).unwrap();
    for block in [&genesis, &next] {
        assert_eq!(db.load_block(block.header().block_num()).await.unwrap(), Some(block.clone()));
        assert_eq!(
            db.load_block_header(block.header().block_num()).await.unwrap(),
            Some(block.header().clone())
        );
    }
    assert_eq!(db.load_block(2.into()).await.unwrap(), None);
}

#[tokio::test]
async fn migration_failure_rolls_back_and_can_be_retried() {
    for failure in ["missing", "corrupt", "mismatch", "format"] {
        let directory = tempfile::tempdir().unwrap();
        let (path, genesis, next) = database_at_version_003(directory.path());
        let file = directory.path().join("blocks/0000/block_00000001.dat");
        match failure {
            "missing" => fs_err::remove_file(&file).unwrap(),
            "corrupt" => fs_err::write(&file, b"invalid block").unwrap(),
            "mismatch" => fs_err::write(&file, miden_node_persistence::encode(&genesis)).unwrap(),
            "format" => fs_err::write(directory.path().join("blocks/format.pb"), [8, 2]).unwrap(),
            _ => unreachable!(),
        }
        assert!(
            migrator().unwrap().open_database(&path).unwrap().migrate_to(4).is_err(),
            "{failure} must fail"
        );
        assert!(load(path.clone()).await.is_err(), "an incomplete migration must not be usable");
        let connection = Connection::open(&path).unwrap();
        assert_eq!(
            connection
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            3
        );
        assert_eq!(
            connection
                .query_row("SELECT count(*) FROM sqlite_schema WHERE name = 'blocks'", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0
        );
        assert_eq!(
            fs_err::read(directory.path().join("blocks/0000/block_00000000.dat")).unwrap(),
            miden_node_persistence::encode(&genesis)
        );
        drop(connection);
        fs_err::write(&file, miden_node_persistence::encode(&next)).unwrap();
        fs_err::write(directory.path().join("blocks/format.pb"), [8, 1]).unwrap();
        migrator().unwrap().open_database(&path).unwrap().migrate_to(4).unwrap();
        let db = open_with_pool_size(&path, NonZeroUsize::new(2).unwrap()).unwrap();
        assert_eq!(db.load_block(1.into()).await.unwrap(), Some(next));
    }
}

#[tokio::test]
async fn migration_preserves_transaction_links_and_replacement_cascades() {
    let directory = tempfile::tempdir().unwrap();
    let (path, _, next) = database_at_version_003(directory.path());
    let transaction_id = TransactionId::from_raw(Word::from([1u32, 0, 0, 0]));
    let record = private_record(transaction_id, 1);
    let legacy = open_with_pool_size(&path, NonZeroUsize::new(2).unwrap()).unwrap();
    legacy.insert_validated_private_transaction(record.clone()).await.unwrap();
    legacy
        .writer
        .write("seed legacy transaction link", move |tx| {
            queries::link_block_transactions(tx, 1.into(), &[transaction_id])
        })
        .await
        .unwrap();
    drop(legacy);

    migrator().unwrap().open_database(&path).unwrap().migrate_to(4).unwrap();
    let db = open_with_pool_size(&path, NonZeroUsize::new(2).unwrap()).unwrap();
    let params = ListTransactionsParams {
        start: None,
        block_to: None,
        limit: 10,
        include_records: true,
    };
    let page = db.list_validated_transactions(params).await.unwrap();
    assert_eq!(page.transactions.len(), 1);
    assert_eq!(page.transactions[0].transaction_id, transaction_id);
    assert_eq!(page.transactions[0].block_num, BlockNumber::from(1u32));
    assert_eq!(page.transactions[0].block_tx_index, 0);
    assert_eq!(page.transactions[0].record.as_ref(), Some(&record));

    let replacement = block_with_header(header_with_next_timestamp(next.header()));
    db.replace_signed_block(replacement.clone(), test_protocol_config(), Vec::new())
        .await
        .unwrap();
    assert_eq!(db.load_block(1.into()).await.unwrap(), Some(replacement));
    assert!(db.list_validated_transactions(params).await.unwrap().transactions.is_empty());
    assert_eq!(db.load_private_record(transaction_id).await.unwrap(), Some(record));
}

#[test]
fn migration_preserves_large_transaction_history() {
    fn links(connection: &Connection) -> Vec<(i64, i64, Vec<u8>)> {
        connection
            .prepare(
                "SELECT block_num, block_tx_index, transaction_id FROM block_transactions
                 ORDER BY block_num, block_tx_index",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    let directory = tempfile::tempdir().unwrap();
    let (path, ..) = database_at_version_003(directory.path());
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch(
            "PRAGMA foreign_keys = ON;
             WITH RECURSIVE positions(n) AS (
                 SELECT 0 UNION ALL SELECT n + 1 FROM positions WHERE n < 20002
             )
             INSERT INTO validated_transactions (
                 id, validator_id, chain_id, key_epoch, setup_context_id, format_version,
                 cipher_nonce, encrypted_record, encrypted_record_key
             )
             SELECT CAST(printf('%032d', n) AS BLOB), zeroblob(33), zeroblob(32), zeroblob(32),
                    zeroblob(32), 1, zeroblob(24), zeroblob(16), zeroblob(1)
             FROM positions;
             INSERT INTO block_transactions (block_num, block_tx_index, transaction_id)
             SELECT (insertion_sequence - 1) / 15001, (insertion_sequence - 1) % 15001, id
             FROM validated_transactions;",
        )
        .unwrap();
    let expected = links(&connection);
    assert_eq!(expected.len(), 20003);

    migrator().unwrap().open_database(&path).unwrap().migrate_to(4).unwrap();

    assert_eq!(links(&connection), expected);
}
