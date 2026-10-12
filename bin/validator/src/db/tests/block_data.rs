use super::*;

#[tokio::test]
async fn block_data_write_failure_rolls_back_insert_and_replacement() {
    let directory = tempfile::tempdir().unwrap();
    let db = setup(directory.path().join("validator.sqlite3")).await.unwrap();
    let original = protocol_config_history::header_at(
        &genesis_header(&ProtocolConfig::mock()),
        1,
        &ProtocolConfig::mock(),
    );
    let original_block = block_with_header(original.clone());
    let original_id = TransactionId::from_raw(Word::from([1u32, 0, 0, 0]));
    let replacement_id = TransactionId::from_raw(Word::from([2u32, 0, 0, 0]));
    for (id, seed) in [(original_id, 1), (replacement_id, 2)] {
        db.insert_validated_private_transaction(private_record(id, seed)).await.unwrap();
    }
    db.insert_signed_block(original_block.clone(), ProtocolConfig::mock(), vec![original_id])
        .await
        .unwrap();
    let initial_history = protocol_config_history::history(&db).await;
    db.writer.write("reject block data", |tx| {
        tx.execute("CREATE TRIGGER reject_block_data BEFORE INSERT ON blocks BEGIN SELECT RAISE(ABORT, 'block data rejected'); END", &[])?;
        Ok::<_, DatabaseError>(())
    }).await.unwrap();
    let replacement = header_with_next_timestamp(&original);
    assert!(
        db.replace_signed_block(
            block_with_header(replacement),
            ProtocolConfig::mock(),
            vec![replacement_id],
        )
        .await
        .is_err()
    );
    let next_config = test_protocol_config();
    let next = protocol_config_history::header_at(&original, 2, &next_config);
    assert!(
        db.insert_signed_block(block_with_header(next), next_config.clone(), vec![replacement_id],)
            .await
            .is_err()
    );
    assert_eq!(db.load_chain_tip().await.unwrap(), Some(original));
    assert_eq!(db.load_block(1.into()).await.unwrap(), Some(original_block));
    assert_eq!(db.load_block(2.into()).await.unwrap(), None);
    assert_eq!(db.load_block_header(2.into()).await.unwrap(), None);
    assert_eq!(protocol_config_history::history(&db).await, initial_history);
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

#[tokio::test]
async fn load_block_rejects_corrupt_data() {
    let directory = tempfile::tempdir().unwrap();
    let db = setup(directory.path().join("validator.sqlite3")).await.unwrap();
    db.writer
        .write("insert corrupt block", |tx| {
            tx.execute(
                "INSERT INTO blocks (block_num, block_header, block_data) VALUES (1, ?1, ?2)",
                &[&BlockHeader::mock(1, None, None, &[]), &b"invalid block".to_vec()],
            )?;
            Ok::<_, DatabaseError>(())
        })
        .await
        .unwrap();

    db.load_block(1.into())
        .await
        .expect_err("corrupt block data must fail at the database boundary");
}
