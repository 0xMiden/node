use miden_node_db::Connection;

use super::*;

#[tokio::test]
async fn migration_preserves_legacy_block_without_inventing_inputs() {
    // Older backups remain readable, but migration cannot reconstruct missing proving material.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("validator.sqlite3");
    crate::db::migrations::migrator()
        .unwrap()
        .create_database(&path)
        .unwrap()
        .migrate_to(4)
        .unwrap();
    let genesis = genesis_block(&test_protocol_config());
    let connection = Connection::open(&path).unwrap();
    connection
        .execute(
            "INSERT INTO blocks (block_num, block_header, block_data) VALUES (?1, ?2, ?3)",
            (
                0,
                miden_node_persistence::encode(genesis.header()),
                miden_node_persistence::encode(&genesis),
            ),
        )
        .unwrap();
    drop(connection);
    assert!(load(path.clone()).await.is_err());
    for _ in 0..2 {
        migrate(&path).unwrap();
        let db = load(path.clone()).await.unwrap();
        let backup = db.load_block_backup(BlockNumber::GENESIS).await.unwrap().unwrap();
        assert_eq!(backup.block, genesis);
        assert!(backup.proving_inputs.is_none());
    }
}
