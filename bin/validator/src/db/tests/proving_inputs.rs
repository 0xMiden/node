use std::collections::BTreeMap;

use miden_protocol::batch::OrderedBatches;
use miden_protocol::block::{BlockInputs, ProposedBlock};
use miden_protocol::transaction::PartialBlockchain;

use super::*;

fn empty_pair(
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
