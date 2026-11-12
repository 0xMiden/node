use miden_node_db::DatabaseError as SqliteDatabaseError;
use miden_node_persistence::{decode, encode};
use miden_protocol::block::code_tree::CodePatch;
use miden_protocol::block::{BlockBody, SignedBlock};
use miden_protocol::transaction::{
    LogTopic,
    PublicTransactionLogs,
    TransactionLog,
    TransactionLogs,
};
use miden_protocol::utils::serde::Serializable;
use pretty_assertions::assert_eq;
use tokio::runtime::Runtime;

use super::*;
use crate::blocks::BlockStore;
use crate::db::migrations::bootstrap_database;
use crate::db::queries::{PreparedTransactionLogs, apply_block, prune_history};

fn log_block() -> SignedBlock {
    let native = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1.try_into().unwrap();
    let emitter = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2.try_into().unwrap();
    let private = ACCOUNT_ID_PRIVATE_SENDER.try_into().unwrap();
    let log = TransactionLog::new(
        emitter,
        LogTopic::new(3_u32.into(), 4_u32.into()),
        vec![num_to_word(7)],
    )
    .unwrap();
    let empty =
        TransactionLog::new(emitter, LogTopic::new(0_u32.into(), 0_u32.into()), vec![]).unwrap();
    let logs = TransactionLogs::new(vec![log.clone(), log, empty]).unwrap();
    let headers: Vec<_> = [private, native, native]
        .into_iter()
        .enumerate()
        .map(|(i, account)| {
            TransactionHeader::new(
                account,
                num_to_word(i as u64 + 1),
                num_to_word(i as u64 + 2),
                InputNotes::default(),
                vec![],
                if i == 1 { logs.commitment() } else { Word::empty() },
                CodePatch::default().commitment(),
            )
            .unwrap()
        })
        .collect();
    let public = PublicTransactionLogs::new(
        vec![(headers[1].id(), logs), (headers[2].id(), TransactionLogs::default())],
        headers.iter(),
    )
    .unwrap();
    let body = BlockBody::new(
        vec![],
        vec![],
        vec![],
        vec![
            OrderedTransactionHeaders::new_unchecked(headers[..2].to_vec()),
            OrderedTransactionHeaders::new_unchecked(headers[2..].to_vec()),
        ],
        public,
    )
    .unwrap();
    let (template, signatures) = mock_block(BlockNumber::ONE);
    let header = BlockHeader::new(
        template.prev_block_commitment(),
        template.block_num(),
        template.chain_commitment(),
        template.account_root(),
        template.nullifier_root(),
        template.code_tree_root(),
        body.compute_block_note_tree().root(),
        body.compute_transactions_commitment(),
        template.validator_config().clone(),
        template.fee_parameters().clone(),
        template.protocol_config_commitment(),
        template.next_protocol_config().cloned(),
        template.timestamp(),
    );
    SignedBlock::new_unchecked(header, body, signatures)
}

fn apply(db: &TestDb, block: SignedBlock) -> Result<usize> {
    let prepared = PreparedTransactionLogs::from_block(block.body())?;
    db.write(move |tx| {
        apply_block(
            tx,
            &block,
            &[],
            &PrecomputedPublicAccountStates::new(),
            &BTreeSet::new(),
            &prepared,
        )
    })
}

#[test]
fn transaction_logs_preserve_order_privacy_and_content_after_restart() {
    let root = tempdir().unwrap();
    let path = root.path().join("store.sqlite3");
    bootstrap_database(&path).unwrap();
    let block = log_block();
    {
        let db = TestDb::open(&path);
        apply(&db, block.clone()).unwrap();
        db.write::<_, DatabaseError, _>(|tx| prune_history(tx, BlockNumber::from(100)))
            .unwrap();
    }
    let block_store =
        BlockStore::bootstrap(root.path().join("blocks"), &empty_genesis_block()).unwrap();
    block_store.save_block_blocking(BlockNumber::ONE, &encode(&block)).unwrap();
    drop(block_store);
    let block_store = BlockStore::load(root.path().join("blocks")).unwrap();
    let bytes = Runtime::new()
        .unwrap()
        .block_on(block_store.load_block(BlockNumber::ONE))
        .unwrap()
        .unwrap();
    let restored: SignedBlock = decode(&bytes).unwrap();
    assert_eq!(restored, block);
    let db = TestDb::open(&path);
    let metadata = db.read::<_, SqliteDatabaseError, _>(|tx| tx.query(
        "SELECT transaction_index, public_log_count, logs_commitment FROM transactions ORDER BY transaction_index", &[],
        |row| Ok((row.get::<u32>(0)?, row.get::<Option<u32>>(1)?, row.get::<Word>(2)?)))).unwrap();
    assert_eq!(
        metadata.iter().map(|(i, c, _)| (*i, *c)).collect::<Vec<_>>(),
        vec![(0, None), (1, Some(3)), (2, Some(0))]
    );
    assert_eq!(metadata[1].2, block.body().public_logs().entries()[0].1.commitment());
    let rows = db.read::<_, SqliteDatabaseError, _>(|tx| tx.query(
        "SELECT native_account_id, block_num, transaction_index, log_index, emitter, topic, content FROM transaction_logs ORDER BY block_num, transaction_index, log_index", &[],
        |row| Ok((row.get::<AccountId>(0)?, row.get::<BlockNumber>(1)?, row.get::<u32>(2)?, row.get::<u32>(3)?, row.get::<AccountId>(4)?, row.get::<Vec<u8>>(5)?, row.get::<Vec<u8>>(6)?)))).unwrap();
    assert_eq!(rows.len(), 3);
    for (i, row) in rows.iter().enumerate() {
        assert_eq!(
            (row.0, row.1, row.2, row.3, row.4),
            (
                ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1.try_into().unwrap(),
                BlockNumber::ONE,
                1,
                i as u32,
                ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2.try_into().unwrap()
            )
        );
    }
    assert_eq!(rows[0].5, [3_u64.to_le_bytes(), 4_u64.to_le_bytes()].concat());
    assert_eq!(rows[0].6, num_to_word(7).to_bytes());
    assert_eq!(rows[0].5, rows[1].5);
    assert_eq!(rows[0].6, rows[1].6);
    assert_eq!(rows[2].5, vec![0; 16]);
    assert_eq!(rows[2].6, [] as [u8; 0]);
}

#[test]
fn transaction_logs_insertion_failure_rolls_back_the_block() {
    let db = TestDb::new();
    db.write::<_, DatabaseError, _>(|tx| {
        tx.execute("CREATE TRIGGER fail_log BEFORE INSERT ON transaction_logs BEGIN SELECT RAISE(ABORT, 'log insert failure'); END", &[])?;
        Ok(())
    }).unwrap();
    assert!(apply(&db, log_block()).is_err());
    let counts = db.read::<_, SqliteDatabaseError, _>(|tx| tx.query(
        "SELECT (SELECT COUNT(*) FROM block_headers), (SELECT COUNT(*) FROM transactions), (SELECT COUNT(*) FROM transaction_logs)", &[],
        |row| Ok((row.get::<u32>(0)?,row.get::<u32>(1)?,row.get::<u32>(2)?)))).unwrap();
    assert_eq!(counts, vec![(0, 0, 0)]);
}
