mod migration_004_block_data;

use super::*;

#[test]
fn migrate_rejects_missing_database() {
    let temp_dir = tempfile::tempdir().expect("failed to create temp directory");
    let db_path = temp_dir.path().join("validator.sqlite3");

    let err = migrate(db_path.clone()).expect_err("missing database should fail");

    assert!(matches!(err, DatabaseError::Migration(_)), "unexpected error: {err:?}");
    assert!(!db_path.exists());
}

/// The protocol configuration migration must preserve headers and private records.
#[tokio::test]
async fn migration_preserves_headers_and_private_records() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("validator.sqlite3");
    crate::db::migrations::migrator()
        .unwrap()
        .create_database(&db_path)
        .unwrap()
        .migrate_to(1)
        .unwrap();

    let config = test_protocol_config();
    let genesis = genesis_block(&config);
    let header = genesis.header().clone();
    let directory = temp_dir.path().join("blocks");
    fs_err::create_dir_all(directory.join("0000")).unwrap();
    fs_err::write(directory.join("format.pb"), [8, 1]).unwrap();
    fs_err::write(
        directory.join("0000/block_00000000.dat"),
        miden_node_persistence::encode(&genesis),
    )
    .unwrap();
    let transaction_id = TransactionId::from_raw(Word::from([1u32, 2, 3, 4]));
    let record = private_record(transaction_id, 1);
    let db = open_with_pool_size(&db_path, NonZeroUsize::new(2).unwrap()).unwrap();
    let stored_header = header.clone();
    db.writer
        .write("seed legacy header", move |tx| {
            tx.execute(
                "INSERT INTO block_headers (block_num, block_header) VALUES (?1, ?2)",
                &[&stored_header.block_num(), &stored_header],
            )?;
            Ok::<_, DatabaseError>(())
        })
        .await
        .unwrap();
    db.insert_validated_private_transaction(record.clone()).await.unwrap();
    drop(db);

    assert!(load(db_path.clone()).await.is_err(), "the old schema requires migration");
    migrate(&db_path).unwrap();
    migrate(&db_path).expect("migration should also accept the latest schema");

    let db = load(db_path).await.unwrap();
    assert_eq!(db.load_chain_tip().await.unwrap(), Some(header.clone()));
    assert_eq!(db.load_private_record(transaction_id).await.unwrap(), Some(record));
    let migrated = db.load_private_record(transaction_id).await.unwrap().unwrap();
    assert_eq!(migrated.context().format_version(), PrivateRecordFormatVersion::V1);
    migrated.verify_encrypted_record_key().unwrap();
    assert_eq!(db.load_protocol_config(config.to_commitment()).await.unwrap(), None);

    db.upsert_block_header_with_protocol_config(header, Some(config.clone()))
        .await
        .unwrap();
    assert_eq!(
        protocol_config_history::history(&db).await,
        vec![(0, config.to_commitment(), config.clone())]
    );
    assert_eq!(db.load_protocol_config(config.to_commitment()).await.unwrap(), Some(config));
}
