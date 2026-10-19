use super::*;

#[tokio::test]
async fn acknowledged_block_retains_inputs_after_restart() {
    // The database retains the proving request after the signing service stops.
    let tv = TestValidator::new().await;
    let upgrade = miden_protocol::protocol_config::NextProtocolConfig::new(
        10.into(),
        tv.protocol_config.to_commitment(),
    )
    .unwrap();
    let proposed = tv.propose_empty_block().with_next_protocol_config(Some(upgrade));
    let expected = proposed.clone().into_header_and_body().unwrap().0;
    tv.call_sign_block(&proposed).await.unwrap();
    let signer = match &tv.server.signer {
        ValidatorSigner::Local(key) => ValidatorSigner::new_local(key.clone()),
        ValidatorSigner::Kms(_) => unreachable!("fixture uses a local signer"),
    };
    let TestValidator { server, temp_dir: directory, .. } = tv;
    drop(server);
    let db = crate::db::load(directory.path().join("validator.sqlite3")).await.unwrap();
    let backup = db.load_block_backup(expected.block_num()).await.unwrap().unwrap();
    assert_eq!(backup.block.header(), &expected);
    backup.proving_inputs.unwrap().validate_against(&backup.block).unwrap();
    let service = ValidatorService::new(
        signer,
        db,
        std::sync::Arc::new(test_decrypter()),
        PrivateRecordSealer::from_operator_key(&operator_keys().remove(0)),
        InitialMetrics {
            chain_tip: expected.block_num().as_u32(),
            ..InitialMetrics::default()
        },
    )
    .await
    .unwrap();
    let mut stream = miden_validator_v1_validator_service::BlockSubscription::full(
        &service,
        tonic::Request::new(proto::miden::validator::v1::BlockSubscriptionRequest {
            block_from: expected.block_num().as_u32(),
        }),
    )
    .await
    .unwrap();
    let response = tokio_stream::StreamExt::next(&mut stream).await.unwrap().unwrap();
    let block: SignedBlock = response.block.unwrap().decode_and_build_unchecked().unwrap();
    let request: miden_node_proto::BlockProofRequest =
        response.proving_inputs.unwrap().decode_and_build_unchecked().unwrap();
    request.validate_against(&block).unwrap();
    assert_eq!(block.header(), &expected);
}

#[tokio::test]
async fn failed_input_commit_does_not_acknowledge_or_publish_tip() {
    // A failed proving input write leaves both the stored and advertised chain tips unchanged.
    let tv = TestValidator::new().await;
    let before = tv.call_status().await;
    let tip = *tv.server.committed_tip.borrow();
    crate::db::reject_proving_input_writes_for_test(&tv.server.db).await.unwrap();
    let error = tv.call_sign_block(&tv.propose_empty_block()).await.unwrap_err();
    assert_eq!(error.code(), tonic::Code::Internal);
    assert_eq!(*tv.server.committed_tip.borrow(), tip);
    assert_eq!(tv.call_status().await.signed_blocks_count, before.signed_blocks_count);
    assert!(tv.server.db.load_block_backup(1.into()).await.unwrap().is_none());
}

#[tokio::test]
async fn replacement_retains_only_matching_inputs_and_corruption_rejects_backup() {
    // A replacement block retains its own proving inputs, and corrupt inputs cause backup reads to
    // fail.
    let tv = TestValidator::new().await;
    let proposal = tv.propose_empty_block();
    tv.call_sign_block(&proposal).await.unwrap();
    let original = tv.server.db.load_block(1.into()).await.unwrap().unwrap();
    let inputs = tv
        .server
        .db
        .load_block_backup(1.into())
        .await
        .unwrap()
        .unwrap()
        .proving_inputs
        .unwrap();
    let original_inputs = miden_node_persistence::encode(&inputs);
    let replacement =
        ProposedBlock::new_at(inputs.block_inputs, vec![], original.header().timestamp() + 1)
            .unwrap();
    tv.call_sign_block(&replacement).await.unwrap();
    let backup = tv.server.db.load_block_backup(1.into()).await.unwrap().unwrap();
    let inputs = backup.proving_inputs.unwrap();
    inputs.validate_against(&backup.block).unwrap();
    assert!(inputs.validate_against(&original).is_err());
    let connection =
        miden_node_db::Connection::open(tv.temp_dir.path().join("validator.sqlite3")).unwrap();
    connection
        .execute("UPDATE blocks SET proving_inputs = ?1 WHERE block_num = 1", [original_inputs])
        .unwrap();
    assert!(tv.server.db.load_block_backup(1.into()).await.is_err());
    connection
        .execute("UPDATE blocks SET proving_inputs = x'ff' WHERE block_num = 1", [])
        .unwrap();
    assert!(tv.server.db.load_block_backup(1.into()).await.is_err());
    assert_eq!(tv.server.db.load_block(1.into()).await.unwrap(), Some(backup.block));
}

#[tokio::test]
async fn backup_retains_requests_across_two_configuration_activations() {
    // Signed blocks retain proving requests under each newly active configuration.
    //
    // Legacy rows model configuration activations because the protocol does not apply scheduled
    // upgrades during block construction.
    use tokio_stream::StreamExt;
    let mut tv = TestValidator::new().await;
    let initial = tv.protocol_config.clone();
    let config = |seed| {
        ProtocolConfig::new(
            initial.fee_asset_id(),
            KernelConfig::new(Word::from([seed, 0, 0, 0]), vec![]).unwrap(),
            initial.batch_kernel().clone(),
            initial.block_kernel().clone(),
            initial.proof_verification().clone(),
        )
        .unwrap()
    };
    let second = config(42u32);
    let third = config(43u32);
    tv.apply_empty_block().await;
    for active in [&second, &third] {
        tv.apply_empty_block().await;
        let old = tv.server.db.load_block(tv.chain_tip.block_num()).await.unwrap().unwrap();
        let (header, body, signatures) = old.into_parts();
        let header = BlockHeader::new(
            header.prev_block_commitment(),
            header.block_num(),
            header.chain_commitment(),
            header.account_root(),
            header.nullifier_root(),
            header.note_root(),
            header.tx_commitment(),
            header.validator_config().clone(),
            header.fee_parameters().clone(),
            active.to_commitment(),
            header.next_protocol_config().cloned(),
            header.timestamp(),
        );
        tv.server
            .db
            .replace_legacy_signed_block(
                SignedBlock::new_unchecked(header.clone(), body, signatures),
                active.clone(),
                vec![],
            )
            .await
            .unwrap();
        tv.chain_tip = header;
        tv.protocol_config = active.clone();
        tv.apply_empty_block().await;
    }
    let mut stream = tv.call_block_subscription(0).await;
    let genesis = stream.next().await.unwrap().unwrap();
    assert!(genesis.proving_inputs.is_none());
    for (height, active, retained) in [
        (1, &initial, true),
        (2, &second, false),
        (3, &second, true),
        (4, &third, false),
        (5, &third, true),
    ] {
        let response = stream.next().await.unwrap().unwrap();
        let block: SignedBlock = response.block.unwrap().decode_and_build_unchecked().unwrap();
        assert_eq!(block.header().block_num().as_u32(), height);
        assert_eq!(block.header().protocol_config_commitment(), active.to_commitment());
        assert_eq!(
            tv.server
                .db
                .load_protocol_config(active.to_commitment())
                .await
                .unwrap()
                .as_ref(),
            Some(active)
        );
        if height == 2 || height == 4 {
            let config: ProtocolConfig =
                response.protocol_config.unwrap().decode_fields().unwrap().verify().unwrap();
            assert_eq!(&config, active);
        } else {
            assert!(response.protocol_config.is_none());
        }
        assert_eq!(response.proving_inputs.is_some(), retained);
        if let Some(inputs) = response.proving_inputs {
            let inputs: miden_node_proto::BlockProofRequest =
                inputs.decode_and_build_unchecked().unwrap();
            inputs.validate_against(&block).unwrap();
        }
    }
    assert!(stream.next().await.is_none());
}

async fn restart_with_retention(tv: TestValidator, retention: u32) -> TestValidator {
    let signer = match &tv.server.signer {
        ValidatorSigner::Local(key) => ValidatorSigner::new_local(key.clone()),
        ValidatorSigner::Kms(_) => unreachable!("fixture uses a local signer"),
    };
    let TestValidator {
        server,
        chain,
        chain_tip,
        protocol_config,
        temp_dir,
    } = tv;
    drop(server);
    let db = crate::db::load_with_retention(
        temp_dir.path().join("validator.sqlite3"),
        std::num::NonZeroUsize::new(2).unwrap(),
        std::num::NonZeroU32::new(retention).unwrap(),
    )
    .await
    .unwrap();
    let server = ValidatorService::new(
        signer,
        db,
        std::sync::Arc::new(test_decrypter()),
        PrivateRecordSealer::from_operator_key(&operator_keys().remove(0)),
        InitialMetrics {
            chain_tip: chain_tip.block_num().as_u32(),
            ..InitialMetrics::default()
        },
    )
    .await
    .unwrap();
    TestValidator {
        server,
        chain,
        chain_tip,
        protocol_config,
        temp_dir,
    }
}

async fn assert_backup_window(tv: &TestValidator, retained: &[u32]) {
    use tokio_stream::StreamExt;
    let mut stream = tv.call_block_subscription(0).await;
    for height in 0..=tv.chain_tip.block_num().as_u32() {
        let response = stream.next().await.unwrap().unwrap();
        let block: SignedBlock = response.block.unwrap().decode_and_build_unchecked().unwrap();
        assert_eq!(block, tv.server.db.load_block(height.into()).await.unwrap().unwrap());
        assert_eq!(
            response.proving_inputs.is_some(),
            retained.contains(&height),
            "inputs at height {height}"
        );
        if let Some(inputs) = response.proving_inputs {
            let inputs: miden_node_proto::BlockProofRequest =
                inputs.decode_and_build_unchecked().unwrap();
            inputs.validate_against(&block).unwrap();
        }
        assert!(
            tv.server
                .db
                .load_protocol_config(block.header().protocol_config_commitment())
                .await
                .unwrap()
                .is_some()
        );
    }
    assert!(stream.next().await.is_none());
}

#[tokio::test]
async fn pruned_backups_stream_signed_blocks_and_recent_inputs_after_restart() {
    let mut tv = TestValidator::new().await;
    for _ in 0..4 {
        tv.apply_empty_block().await;
    }
    assert_backup_window(&tv, &[1, 2, 3, 4]).await;
    let mut tv = restart_with_retention(tv, 2).await;
    assert_backup_window(&tv, &[3, 4]).await;
    tv.apply_empty_block().await;
    assert_backup_window(&tv, &[4, 5]).await;
    let tv = restart_with_retention(tv, 2).await;
    assert_backup_window(&tv, &[4, 5]).await;
}

#[tokio::test]
async fn pruning_failure_does_not_acknowledge_or_publish_a_new_tip() {
    let mut tv = restart_with_retention(TestValidator::new().await, 1).await;
    tv.apply_empty_block().await;
    let before = tv.call_status().await;
    let tip = *tv.server.committed_tip.borrow();
    let connection =
        miden_node_db::Connection::open(tv.temp_dir.path().join("validator.sqlite3")).unwrap();
    connection.execute("CREATE TRIGGER reject_pruning BEFORE UPDATE OF proving_inputs ON blocks WHEN OLD.proving_inputs IS NOT NULL AND NEW.proving_inputs IS NULL BEGIN SELECT RAISE(ABORT, 'pruning rejected'); END", []).unwrap();
    let error = tv.call_sign_block(&tv.propose_empty_block()).await.unwrap_err();
    assert_eq!(error.code(), tonic::Code::Internal);
    assert_eq!(*tv.server.committed_tip.borrow(), tip);
    assert_eq!(tv.call_status().await.signed_blocks_count, before.signed_blocks_count);
    assert!(
        tv.server
            .db
            .load_block_backup(1.into())
            .await
            .unwrap()
            .unwrap()
            .proving_inputs
            .is_some()
    );
    assert!(tv.server.db.load_block_backup(2.into()).await.unwrap().is_none());
    connection.execute("DROP TRIGGER reject_pruning", []).unwrap();
    drop(connection);
    tv.apply_empty_block().await;
    assert_backup_window(&tv, &[2]).await;
}
