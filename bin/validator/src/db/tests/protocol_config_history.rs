use super::*;

fn config(seed: u32) -> ProtocolConfig {
    use miden_protocol::protocol_config::KernelConfig;

    let base = test_protocol_config();
    ProtocolConfig::new(
        base.fee_asset_id(),
        KernelConfig::new(Word::from([seed, 0, 0, 0]), vec![]).unwrap(),
        base.batch_kernel().clone(),
        base.block_kernel().clone(),
        base.proof_verification().clone(),
    )
    .unwrap()
}

fn header_at(base: &BlockHeader, height: u32, config: &ProtocolConfig) -> BlockHeader {
    BlockHeader::new(
        base.commitment(),
        height.into(),
        base.chain_commitment(),
        base.account_root(),
        base.nullifier_root(),
        base.note_root(),
        base.tx_commitment(),
        base.validator_config().clone(),
        base.fee_parameters().clone(),
        config.to_commitment(),
        base.next_protocol_config().cloned(),
        base.timestamp() + 1,
    )
}

pub(super) async fn history(db: &ValidatorDbWriter) -> Vec<(i64, Word, ProtocolConfig)> {
    db.reader.reader.read("activation_history", |tx| {
        tx.query(
            "SELECT block_number, commitment, protocol_config FROM protocol_configs ORDER BY block_number",
            &[],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
    }).await.unwrap()
}

#[tokio::test]
async fn activations_include_reused_configs_and_survive_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("validator.sqlite3");
    let first = test_protocol_config();
    let second = config(42);
    let genesis = genesis_header(&first);
    bootstrap(path.clone(), NonZeroUsize::new(2).unwrap(), genesis.clone(), first.clone())
        .await
        .unwrap();
    let db = load(path.clone()).await.unwrap();
    let mut parent = genesis;
    for (height, active, supplied) in
        [(1, &first, true), (2, &second, true), (3, &second, false), (4, &first, false)]
    {
        let header = header_at(&parent, height, active);
        db.upsert_block_header_with_protocol_config(
            header.clone(),
            supplied.then(|| active.clone()),
        )
        .await
        .unwrap();
        parent = header;
    }
    let expected = vec![
        (0, first.to_commitment(), first.clone()),
        (2, second.to_commitment(), second),
        (4, first.to_commitment(), first.clone()),
    ];
    assert_eq!(history(&db).await, expected);
    assert_eq!(db.load_protocol_config(first.to_commitment()).await.unwrap(), Some(first));
    drop(db);
    let db = load(path).await.unwrap();
    assert_eq!(history(&db).await, expected);
    assert_eq!(db.load_chain_tip().await.unwrap(), Some(parent));
}

#[tokio::test]
async fn repeated_tip_writes_preserve_activation() {
    let dir = tempfile::tempdir().unwrap();
    let db = setup(dir.path().join("validator.sqlite3")).await.unwrap();
    let first = test_protocol_config();
    let second = config(42);
    let genesis = genesis_header(&first);
    db.upsert_block_header_with_protocol_config(genesis.clone(), Some(first.clone()))
        .await
        .unwrap();
    let tip = header_at(&genesis, 1, &second);
    db.upsert_block_header_with_protocol_config(tip.clone(), Some(second.clone()))
        .await
        .unwrap();
    db.upsert_block_header_with_protocol_config(tip.clone(), None).await.unwrap();
    let tip = header_with_next_timestamp(&tip);
    db.upsert_block_header_with_protocol_config(tip.clone(), Some(second.clone()))
        .await
        .unwrap();
    assert_eq!(
        history(&db).await,
        vec![(0, first.to_commitment(), first.clone()), (1, second.to_commitment(), second),]
    );
    assert_eq!(db.load_chain_tip().await.unwrap(), Some(tip));
}

#[tokio::test]
async fn invalid_configs_preserve_existing_history() {
    let dir = tempfile::tempdir().unwrap();
    let db = setup(dir.path().join("validator.sqlite3")).await.unwrap();
    let first = test_protocol_config();
    let second = config(42);
    let genesis = genesis_header(&first);
    db.upsert_block_header_with_protocol_config(genesis.clone(), Some(first.clone()))
        .await
        .unwrap();
    let before = history(&db).await;
    for supplied in [None, Some(first)] {
        db.upsert_block_header_with_protocol_config(header_at(&genesis, 1, &second), supplied)
            .await
            .unwrap_err();
        assert_eq!(history(&db).await, before);
        assert_eq!(db.load_chain_tip().await.unwrap(), Some(genesis.clone()));
    }
}
