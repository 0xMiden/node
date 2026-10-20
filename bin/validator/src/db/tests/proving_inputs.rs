use std::collections::BTreeMap;

use miden_protocol::batch::OrderedBatches;
use miden_protocol::block::{BlockInputs, ProposedBlock};
use miden_protocol::transaction::PartialBlockchain;

use super::*;

pub(super) fn empty_pair(
    parent: &BlockHeader,
    chain: PartialBlockchain,
    timestamp: u32,
) -> (SignedBlock, BlockProofRequest) {
    let block_inputs =
        BlockInputs::new(parent.clone(), chain, BTreeMap::new(), BTreeMap::new(), BTreeMap::new());
    let proposal = ProposedBlock::new_at(block_inputs.clone(), vec![], timestamp).unwrap();
    let (header, body) = proposal.into_header_and_body().unwrap();
    let inputs = BlockProofRequest {
        tx_batches: OrderedBatches::new(vec![]),
        block_header: header.clone(),
        block_inputs,
    };
    let block = SignedBlock::new_unchecked(
        header,
        body,
        genesis_block(&test_protocol_config()).signatures().clone(),
    );
    inputs.validate_against(&block).unwrap();
    (block, inputs)
}

#[tokio::test]
async fn proving_input_failure_rolls_back_blocks_links_and_configuration_history() {
    // A failed proving input write rolls back the block, transaction links, and configuration
    // history, including deletion of a replaced block.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("validator.sqlite3");
    let db = setup(path.clone()).await.unwrap();
    let config = test_protocol_config();
    let genesis = genesis_header(&config);
    let (original, inputs) =
        empty_pair(&genesis, PartialBlockchain::default(), genesis.timestamp() + 1);
    let expected_inputs = miden_node_persistence::encode(&inputs);
    let original_id = TransactionId::from_raw(Word::from([1u32, 0, 0, 0]));
    let replacement_id = TransactionId::from_raw(Word::from([2u32, 0, 0, 0]));
    for (id, seed) in [(original_id, 1), (replacement_id, 2)] {
        db.insert_validated_private_transaction(private_record(id, seed)).await.unwrap();
    }
    db.insert_signed_block(original.clone(), config.clone(), vec![original_id], inputs)
        .await
        .unwrap();
    let history = protocol_config_history::history(&db).await;
    reject_proving_input_writes_for_test(&db).await.unwrap();
    let (replacement, inputs) =
        empty_pair(&genesis, PartialBlockchain::default(), genesis.timestamp() + 2);
    assert!(
        db.replace_signed_block(replacement, config.clone(), vec![replacement_id], inputs)
            .await
            .is_err()
    );
    let mut chain = PartialBlockchain::default();
    chain.add_block(&genesis, false);
    let (next, inputs) = empty_pair(original.header(), chain, original.header().timestamp() + 1);
    assert!(
        db.insert_signed_block(next, config, vec![replacement_id], inputs)
            .await
            .is_err()
    );
    db.writer
        .write("remove failure trigger", |tx| {
            tx.execute("DROP TRIGGER reject_proving_inputs", &[])?;
            Ok::<_, DatabaseError>(())
        })
        .await
        .unwrap();
    drop(db);
    let db = load(path).await.unwrap();
    let backup = db.load_block_backup(1.into()).await.unwrap().unwrap();
    assert_eq!(backup.block, original);
    assert_eq!(
        miden_node_persistence::encode(backup.proving_inputs.as_ref().unwrap()),
        expected_inputs
    );
    assert!(db.load_block_backup(2.into()).await.unwrap().is_none());
    assert_eq!(protocol_config_history::history(&db).await, history);
    let page = db
        .list_validated_transactions(ListTransactionsParams {
            start: None,
            block_to: None,
            limit: 10,
            include_records: false,
        })
        .await
        .unwrap();
    assert_eq!(page.transactions.len(), 1);
    assert_eq!(page.transactions[0].transaction_id, original_id);
}

async fn retained_db(path: PathBuf, retention: u32) -> ValidatorDbWriter {
    load_with_retention(path, NonZeroUsize::new(2).unwrap(), NonZeroU32::new(retention).unwrap())
        .await
        .unwrap()
}

async fn append_empty_block(db: &ValidatorDbWriter) -> (SignedBlock, BlockProofRequest) {
    let config = test_protocol_config();
    let parent = db.load_chain_tip().await.unwrap().unwrap();
    let mut chain = PartialBlockchain::default();
    for height in 0..parent.block_num().as_u32() {
        chain.add_block(&db.load_block_header(height.into()).await.unwrap().unwrap(), false);
    }
    let (block, inputs) = empty_pair(&parent, chain, parent.timestamp() + 1);
    let retained_inputs =
        miden_node_persistence::decode(&miden_node_persistence::encode(&inputs)).unwrap();
    db.insert_signed_block(block.clone(), config, vec![], inputs).await.unwrap();
    (block, retained_inputs)
}

async fn assert_inputs(db: &ValidatorDbWriter, expected: &[(u32, bool)]) {
    for &(height, retained) in expected {
        let backup = db.load_block_backup(height.into()).await.unwrap().unwrap();
        assert_eq!(backup.block.header().block_num().as_u32(), height);
        assert_eq!(backup.proving_inputs.is_some(), retained, "inputs at height {height}");
        if let Some(inputs) = backup.proving_inputs {
            inputs.validate_against(&backup.block).unwrap();
        }
    }
}

#[tokio::test]
async fn retention_prunes_at_the_age_boundary_and_preserves_backups() {
    for retention in [1, 2] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("validator.sqlite3");
        let config = test_protocol_config();
        bootstrap(path.clone(), NonZeroUsize::new(2).unwrap(), genesis_block(&config), config)
            .await
            .unwrap();
        let db = retained_db(path, retention).await;
        append_empty_block(&db).await;
        assert_inputs(&db, &[(0, false), (1, true)]).await;
        append_empty_block(&db).await;
        assert_inputs(&db, &[(1, retention == 2), (2, true)]).await;
        append_empty_block(&db).await;
        assert_inputs(&db, &[(1, false), (2, retention == 2), (3, true)]).await;
        append_empty_block(&db).await;
        assert_inputs(&db, &[(1, false), (2, false), (3, retention == 2), (4, true)]).await;
        assert!(
            db.load_protocol_config(test_protocol_config().to_commitment())
                .await
                .unwrap()
                .is_some()
        );
    }
}

#[tokio::test]
async fn restart_applies_a_smaller_window_without_restoring_pruned_inputs() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("validator.sqlite3");
    let config = test_protocol_config();
    bootstrap(path.clone(), NonZeroUsize::new(2).unwrap(), genesis_block(&config), config)
        .await
        .unwrap();
    let db = retained_db(path.clone(), 10).await;
    for _ in 0..4 {
        append_empty_block(&db).await;
    }
    assert_inputs(&db, &[(1, true), (2, true), (3, true), (4, true)]).await;
    drop(db);
    for window in [2, 2, 10] {
        let db = retained_db(path.clone(), window).await;
        assert_inputs(&db, &[(0, false), (1, false), (2, false), (3, true), (4, true)]).await;
    }
}

#[tokio::test]
async fn tip_replacement_preserves_the_retention_boundary() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("validator.sqlite3");
    let config = test_protocol_config();
    bootstrap(
        path.clone(),
        NonZeroUsize::new(2).unwrap(),
        genesis_block(&config),
        config.clone(),
    )
    .await
    .unwrap();
    let db = retained_db(path, 2).await;
    append_empty_block(&db).await;
    append_empty_block(&db).await;
    let (original, inputs) = append_empty_block(&db).await;
    let replacement = ProposedBlock::new_at(
        inputs.block_inputs.clone(),
        vec![],
        original.header().timestamp() + 1,
    )
    .unwrap();
    let (header, body) = replacement.into_header_and_body().unwrap();
    let replacement =
        SignedBlock::new_unchecked(header.clone(), body, original.signatures().clone());
    let inputs = BlockProofRequest { block_header: header, ..inputs };
    db.replace_signed_block(replacement.clone(), config, vec![], inputs)
        .await
        .unwrap();
    assert_inputs(&db, &[(1, false), (2, true), (3, true)]).await;
    assert_eq!(db.load_block(3.into()).await.unwrap().unwrap(), replacement);
}

#[tokio::test]
async fn pruning_failure_rolls_back_the_block_and_is_retryable_on_startup() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("validator.sqlite3");
    let config = test_protocol_config();
    bootstrap(
        path.clone(),
        NonZeroUsize::new(2).unwrap(),
        genesis_block(&config),
        config.clone(),
    )
    .await
    .unwrap();
    let db = retained_db(path.clone(), 1).await;
    let (original, _) = append_empty_block(&db).await;
    let transaction_id = TransactionId::from_raw(Word::from([1u32, 0, 0, 0]));
    db.insert_validated_private_transaction(private_record(transaction_id, 1))
        .await
        .unwrap();
    let history = protocol_config_history::history(&db).await;
    db.writer.write("reject pruning", |tx| {
        tx.execute("CREATE TRIGGER reject_pruning BEFORE UPDATE OF proving_inputs ON blocks WHEN OLD.proving_inputs IS NOT NULL AND NEW.proving_inputs IS NULL BEGIN SELECT RAISE(ABORT, 'pruning rejected'); END", &[])?;
        Ok::<_, DatabaseError>(())
    }).await.unwrap();
    let mut chain = PartialBlockchain::default();
    chain.add_block(&db.load_block_header(0.into()).await.unwrap().unwrap(), false);
    let (next, inputs) = empty_pair(original.header(), chain, original.header().timestamp() + 1);
    let retained_inputs = miden_node_persistence::decode::<BlockProofRequest>(
        &miden_node_persistence::encode(&inputs),
    )
    .unwrap();
    assert!(
        db.insert_signed_block(next.clone(), config.clone(), vec![transaction_id], inputs)
            .await
            .is_err()
    );
    assert_eq!(db.load_chain_tip().await.unwrap().unwrap(), *original.header());
    assert_inputs(&db, &[(1, true)]).await;
    assert!(db.load_block(2.into()).await.unwrap().is_none());
    assert_eq!(protocol_config_history::history(&db).await, history);
    let page = db
        .list_validated_transactions(ListTransactionsParams {
            start: None,
            block_to: None,
            limit: 10,
            include_records: true,
        })
        .await
        .unwrap();
    assert!(page.transactions.is_empty());
    assert!(db.load_private_record(transaction_id).await.unwrap().is_some());
    // Seed an expired backlog to exercise the cleanup used during startup.
    db.writer
        .write("seed backlog", move |tx| {
            persist_signed_block(tx, &next, config, &[transaction_id], Some(&retained_inputs))
        })
        .await
        .unwrap();
    assert!(db.prune_expired_proving_inputs().await.is_err());
    assert_inputs(&db, &[(1, true), (2, true)]).await;
    drop(db);
    let connection = miden_node_db::Connection::open(&path).unwrap();
    connection.execute("DROP TRIGGER reject_pruning", []).unwrap();
    drop(connection);
    let db = retained_db(path, 1).await;
    assert_inputs(&db, &[(1, false), (2, true)]).await;
    append_empty_block(&db).await;
    assert_inputs(&db, &[(2, false), (3, true)]).await;
    let page = db
        .list_validated_transactions(ListTransactionsParams {
            start: None,
            block_to: None,
            limit: 10,
            include_records: true,
        })
        .await
        .unwrap();
    assert_eq!(page.transactions.len(), 1);
    assert_eq!(page.transactions[0].transaction_id, transaction_id);
    assert_eq!(page.transactions[0].block_num, BlockNumber::from(2u32));
    assert!(db.load_private_record(transaction_id).await.unwrap().is_some());
}

#[tokio::test]
async fn backup_snapshot_keeps_inputs_while_new_reads_observe_pruning() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("validator.sqlite3");
    let config = test_protocol_config();
    bootstrap(path.clone(), NonZeroUsize::new(2).unwrap(), genesis_block(&config), config)
        .await
        .unwrap();
    let db = retained_db(path, 1).await;
    append_empty_block(&db).await;
    let snapshot = db.reader.reader.begin_read().await.unwrap();
    let before = snapshot
        .run("pin backup", |tx| queries::load_block_backup(tx, 1.into()))
        .await
        .unwrap()
        .unwrap();
    assert!(before.proving_inputs.is_some());
    append_empty_block(&db).await;
    let pinned = snapshot
        .run("read pinned backup", |tx| queries::load_block_backup(tx, 1.into()))
        .await
        .unwrap()
        .unwrap();
    assert!(pinned.proving_inputs.is_some());
    assert_eq!(pinned.block, before.block);
    assert_inputs(&db, &[(1, false), (2, true)]).await;
}

#[tokio::test]
async fn ordinary_database_open_preserves_inputs_until_retention_is_selected() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("validator.sqlite3");
    let config = test_protocol_config();
    bootstrap(
        path.clone(),
        NonZeroUsize::new(2).unwrap(),
        genesis_block(&config),
        config.clone(),
    )
    .await
    .unwrap();
    let db = retained_db(path.clone(), 20_000).await;
    let (block, _) = append_empty_block(&db).await;
    let tip = protocol_config_history::header_at(block.header(), 10_001, &config);
    db.upsert_block_header_with_protocol_config(tip, Some(config)).await.unwrap();
    drop(db);
    let db = load(path.clone()).await.unwrap();
    assert_inputs(&db, &[(1, true)]).await;
    drop(db);
    let db = retained_db(path, 10_000).await;
    assert_inputs(&db, &[(1, false)]).await;
}
