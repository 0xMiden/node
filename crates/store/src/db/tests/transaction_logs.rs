use miden_node_db::DatabaseError as SqliteDatabaseError;
use miden_node_persistence::{decode, encode};
use miden_node_proto::domain::transaction_logs::GetTransactionLogsResponse;
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

fn lookup(
    db: &TestDb,
    header: &TransactionHeader,
    tip: BlockNumber,
) -> Result<Option<GetTransactionLogsResponse>, DatabaseError> {
    use crate::db::queries::select_transaction_logs;
    use crate::state::ScopedBlockNum;
    let account = header.account_id();
    let id = header.id();
    db.read(move |tx| select_transaction_logs(tx, account, id, ScopedBlockNum::new_unchecked(tip)))
}

#[test]
fn lookup_preserves_visibility_positions_and_native_ownership() {
    use crate::db::queries::select_transaction_logs;
    use crate::state::ScopedBlockNum;
    let root = tempdir().unwrap();
    let path = root.path().join("store.sqlite3");
    bootstrap_database(&path).unwrap();
    let block = log_block();
    {
        let db = TestDb::open(&path);
        apply(&db, block.clone()).unwrap();
    }
    let db = TestDb::open(&path);
    let headers: Vec<_> = block
        .body()
        .transactions()
        .iter()
        .flat_map(OrderedTransactionHeaders::as_slice)
        .collect();
    for (index, header) in headers.iter().enumerate() {
        let result = lookup(&db, header, BlockNumber::ONE).unwrap().unwrap();
        assert_eq!(result.transaction_id, header.id());
        assert_eq!(result.native_account_id, header.account_id());
        assert_eq!(result.block_num, BlockNumber::ONE);
        assert_eq!(result.transaction_index, index as u32);
        assert_eq!(result.logs_commitment, header.logs_commitment());
        match index {
            0 => assert!(result.logs.is_none()),
            1 => {
                let logs = result.logs.unwrap();
                assert_eq!(
                    logs,
                    block.body().public_logs().entries()[0].1.iter().cloned().collect::<Vec<_>>()
                );
                assert_ne!(logs[0].emitter(), header.account_id());
            },
            2 => assert_eq!(result.logs, Some(vec![])),
            _ => unreachable!(),
        }
        assert!(lookup(&db, header, BlockNumber::GENESIS).unwrap().is_none());
    }
    let wrong: AccountId = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2.try_into().unwrap();
    let id = headers[1].id();
    let native = headers[1].account_id();
    let result = db
        .read::<_, DatabaseError, _>(move |tx| {
            select_transaction_logs(tx, wrong, id, ScopedBlockNum::new_unchecked(BlockNumber::ONE))
        })
        .unwrap();
    assert!(result.is_none());
    let missing = TransactionId::from_raw(num_to_word(1234));
    let result = db
        .read::<_, DatabaseError, _>(move |tx| {
            select_transaction_logs(
                tx,
                native,
                missing,
                ScopedBlockNum::new_unchecked(BlockNumber::ONE),
            )
        })
        .unwrap();
    assert!(result.is_none());
}

#[test]
fn lookup_rejects_corrupt_log_collections() {
    let corruptions = [
        "UPDATE transactions SET public_log_count = 2 WHERE transaction_index = 1",
        "UPDATE transactions SET public_log_count = 65 WHERE transaction_index = 1",
        "INSERT INTO transaction_logs SELECT native_account_id, block_num, transaction_index, 64, transaction_id, emitter, topic, content FROM transaction_logs WHERE log_index = 0",
        "WITH RECURSIVE positions(i) AS (SELECT 3 UNION ALL SELECT i + 1 FROM positions WHERE i < 64) INSERT INTO transaction_logs SELECT native_account_id, block_num, transaction_index, i, transaction_id, emitter, topic, content FROM transaction_logs CROSS JOIN positions WHERE log_index = 0",
        "UPDATE transactions SET public_log_count = NULL WHERE transaction_index = 1",
        "UPDATE transactions SET public_log_count = 0 WHERE transaction_index = 0",
        "UPDATE transaction_logs SET native_account_id = (SELECT account_id FROM transactions WHERE transaction_index = 0), transaction_index = 0, transaction_id = (SELECT transaction_id FROM transactions WHERE transaction_index = 0) WHERE log_index = 0",
        "UPDATE transaction_logs SET log_index = 8 WHERE log_index = 2",
        "UPDATE transaction_logs SET transaction_id = (SELECT transaction_id FROM transactions WHERE transaction_index = 2) WHERE log_index = 0",
        "UPDATE transaction_logs SET emitter = zeroblob(15) WHERE log_index = 0",
        "UPDATE transaction_logs SET emitter = zeroblob(1000000) WHERE log_index = 0",
        "UPDATE transaction_logs SET topic = CAST(zeroblob(16) AS TEXT) WHERE log_index = 0",
        "UPDATE transaction_logs SET topic = zeroblob(7) WHERE log_index = 0",
        "UPDATE transaction_logs SET topic = zeroblob(1000000) WHERE log_index = 0",
        "UPDATE transaction_logs SET topic = X'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF' WHERE log_index = 0",
        "UPDATE transaction_logs SET content = zeroblob(1000000) WHERE log_index = 0",
        "UPDATE transaction_logs SET content = zeroblob(31) WHERE log_index = 0",
        "UPDATE transaction_logs SET content = X'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF' WHERE log_index = 0",
        "UPDATE transaction_logs SET content = zeroblob(2048) WHERE log_index < 2",
        "UPDATE transactions SET logs_commitment = zeroblob(31) WHERE transaction_index = 1",
    ];
    for sql in corruptions {
        let db = TestDb::new();
        let block = log_block();
        apply(&db, block.clone()).unwrap();
        db.write::<_, DatabaseError, _>(move |tx| {
            tx.execute("PRAGMA ignore_check_constraints = ON", &[])?;
            tx.execute(sql, &[])?;
            Ok(())
        })
        .unwrap();
        let header = if sql.contains("transaction_index = 0") {
            &block.body().transactions()[0].as_slice()[0]
        } else {
            &block.body().transactions()[0].as_slice()[1]
        };
        assert!(lookup(&db, header, BlockNumber::ONE).is_err(), "{sql}");
    }
}

#[test]
fn lookup_accepts_the_protocol_log_and_content_limits() {
    let db = TestDb::new();
    let block = log_block();
    apply(&db, block.clone()).unwrap();
    db.write::<_, DatabaseError, _>(|tx| {
        tx.execute("UPDATE transaction_logs SET content = zeroblob(32) WHERE log_index < 2", &[])?;
        tx.execute("WITH RECURSIVE positions(i) AS (SELECT 3 UNION ALL SELECT i + 1 FROM positions WHERE i < 63) INSERT INTO transaction_logs SELECT native_account_id, block_num, transaction_index, i, transaction_id, emitter, topic, content FROM transaction_logs CROSS JOIN positions WHERE log_index = 0", &[])?;
        tx.execute("UPDATE transaction_logs SET content = zeroblob(32) WHERE log_index = 2", &[])?;
        tx.execute("UPDATE transactions SET public_log_count = 64 WHERE transaction_index = 1", &[])?;
        Ok(())
    }).unwrap();
    let header = &block.body().transactions()[0].as_slice()[1];
    let response = lookup(&db, header, BlockNumber::ONE).unwrap().unwrap();
    let logs = response.logs.unwrap();
    assert_eq!(logs.len(), TransactionLogs::MAX_COUNT);
    assert_eq!(
        logs.iter().map(|log| log.content().len()).sum::<usize>(),
        TransactionLogs::MAX_NUM_WORDS
    );
    assert_eq!(response.logs_commitment, header.logs_commitment());
}
