use rusqlite::Connection;

use super::*;

#[tokio::test(flavor = "multi_thread")]
async fn transaction_logs_are_queryable_over_grpc_by_native_account() {
    use miden_node_proto::generated::miden::node::v1::GetTransactionLogsRequest;
    use miden_node_proto::generated::transaction::transaction_log_details::Visibility;
    let (mut client, _, mut store, _server) = start_rpc().await;
    let (parent, _) = store.state.view().get_block_header(None, false).await.unwrap();
    let config = store
        .state
        .view()
        .get_protocol_config(parent.unwrap().protocol_config_commitment())
        .await
        .unwrap()
        .unwrap();
    let template = next_block_with_protocol_config(&store, &config).await;
    let block = block_with_mixed_logs(&template);
    let expected = &block.body().public_logs().entries()[0].1;
    let transaction = &block.body().transactions()[0].as_slice()[0];
    let request = GetTransactionLogsRequest {
        native_account_id: Some(transaction.account_id().into()),
        transaction_id: Some(transaction.id().into()),
    };
    let status = client.get_transaction_logs(request.clone()).await.unwrap_err();
    assert_eq!(status.code(), Code::NotFound);
    assert_eq!(status.details(), &[2]);
    store.writer.apply_block(block.clone(), None).await.unwrap();
    let response = client.get_transaction_logs(request.clone()).await.unwrap().into_inner();
    assert_eq!(response.logs_commitment, Some(transaction.logs_commitment().into()));
    assert_eq!(response.block_num, block.header().block_num().as_u32());
    assert_eq!(response.transaction_index, 0);
    let Visibility::Public(actual) = response.log_details.unwrap().visibility.unwrap() else {
        panic!("expected public logs")
    };
    assert_eq!(actual.logs, expected.iter().map(Into::into).collect::<Vec<_>>());
    let wrong: AccountId = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into().unwrap();
    let mut mismatch = request.clone();
    mismatch.native_account_id = Some(wrong.into());
    let status = client.get_transaction_logs(mismatch).await.unwrap_err();
    assert_eq!(status.code(), Code::NotFound);
    assert_eq!(status.details(), &[2]);
    for header in &block.body().transactions()[0].as_slice()[1..] {
        let result = client
            .get_transaction_logs(GetTransactionLogsRequest {
                native_account_id: Some(header.account_id().into()),
                transaction_id: Some(header.id().into()),
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(result.logs_commitment, Some(header.logs_commitment().into()));
        match result.log_details.unwrap().visibility.unwrap() {
            Visibility::Private(commitment) => {
                assert!(!header.account_id().is_public());
                assert_eq!(commitment, header.logs_commitment().into());
            },
            Visibility::Public(logs) => {
                assert!(header.account_id().is_public());
                assert_eq!(logs.logs, []);
            },
        }
    }
    let db_path = DataDirectory::load(store.data_directory.clone()).unwrap().database_path();
    Connection::open(&db_path)
        .unwrap()
        .execute("ALTER TABLE transaction_logs RENAME TO unavailable_transaction_logs", [])
        .unwrap();
    let error = client.get_transaction_logs(request.clone()).await.unwrap_err();
    assert_eq!(error.code(), Code::Internal);
    assert_eq!(error.details(), &[0]);
    assert_eq!(error.message(), "Failed to read transaction logs");
    Connection::open(&db_path)
        .unwrap()
        .execute("ALTER TABLE unavailable_transaction_logs RENAME TO transaction_logs", [])
        .unwrap();
    assert!(client.get_transaction_logs(request.clone()).await.is_ok());
    for invalid in [
        GetTransactionLogsRequest::default(),
        GetTransactionLogsRequest {
            native_account_id: None,
            ..request.clone()
        },
        GetTransactionLogsRequest { transaction_id: None, ..request },
    ] {
        let status = client.get_transaction_logs(invalid).await.unwrap_err();
        assert_eq!(status.code(), Code::InvalidArgument);
        assert_eq!(status.details(), &[1]);
    }
}

fn block_with_mixed_logs(template: &SignedBlock) -> SignedBlock {
    use miden_node_proto::DecodeMessageExt;
    use miden_node_proto::generated::blockchain::SignedBlock as ProtoSignedBlock;
    use miden_protocol::block::BlockBody;
    use miden_protocol::testing::account_id::{
        ACCOUNT_ID_PRIVATE_SENDER,
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
    };
    use miden_protocol::transaction::{
        InputNotes,
        LogTopic,
        OrderedTransactionHeaders,
        TransactionHeader,
        TransactionLog,
    };
    let native = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1.try_into().unwrap();
    let private = ACCOUNT_ID_PRIVATE_SENDER.try_into().unwrap();
    let log = TransactionLog::new(
        private,
        LogTopic::new(3_u32.into(), 4_u32.into()),
        vec![Word::from([7_u32; 4])],
    )
    .unwrap();
    let empty =
        TransactionLog::new(private, LogTopic::new(0_u32.into(), 0_u32.into()), vec![]).unwrap();
    let logs = TransactionLogs::new(vec![log.clone(), log, empty]).unwrap();
    let headers: Vec<_> = [native, native, private]
        .into_iter()
        .enumerate()
        .map(|(index, account)| {
            TransactionHeader::new(
                account,
                Word::from([index as u32 + 1; 4]),
                Word::from([index as u32 + 2; 4]),
                InputNotes::default(),
                vec![],
                if index == 0 { logs.commitment() } else { Word::empty() },
                CodePatch::default().commitment(),
            )
            .unwrap()
        })
        .collect();
    let public = PublicTransactionLogs::new(
        vec![(headers[0].id(), logs), (headers[1].id(), TransactionLogs::default())],
        headers.iter(),
    )
    .unwrap();
    let body = BlockBody::new(
        vec![],
        vec![],
        vec![],
        vec![OrderedTransactionHeaders::new_unchecked(headers)],
        public,
    )
    .unwrap();
    let mut wire = ProtoSignedBlock::from(template);
    let header = wire.header.as_mut().unwrap();
    header.tx_commitment = Some(body.compute_transactions_commitment().into());
    header.note_root = Some(body.compute_block_note_tree().root().into());
    wire.body = Some((&body).into());
    wire.decode_and_build_unchecked().unwrap()
}
