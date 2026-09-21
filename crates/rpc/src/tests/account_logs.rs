use super::*;

#[tokio::test]
async fn account_logs_require_an_account_and_validate_query_bounds() {
    let (mut rpc, _, _store, _server) = start_rpc().await;
    let account: AccountId = ACCOUNT_ID_SENDER.try_into().unwrap();
    let valid = proto::rpc::GetAccountLogsRequest {
        account_id: Some(account.into()),
        block_range: Some(proto::rpc::BlockRange { block_from: 0, block_to: 0 }),
        ..Default::default()
    };
    let page = rpc.get_account_logs(valid.clone()).await.unwrap().into_inner();
    assert!(page.records.is_empty());
    assert!(page.next_cursor.is_none());
    assert_eq!(page.chain_tip, 0);

    for invalid in [
        proto::rpc::GetAccountLogsRequest { account_id: None, ..valid.clone() },
        proto::rpc::GetAccountLogsRequest { block_range: None, ..valid.clone() },
        proto::rpc::GetAccountLogsRequest {
            account_id: Some(proto::account::AccountId::default()),
            ..valid.clone()
        },
        proto::rpc::GetAccountLogsRequest { topic: Some(vec![0; 8]), ..valid.clone() },
        proto::rpc::GetAccountLogsRequest {
            topic: Some(vec![255; 16]),
            ..valid.clone()
        },
        proto::rpc::GetAccountLogsRequest { page_size: 257, ..valid.clone() },
        proto::rpc::GetAccountLogsRequest {
            after: Some(proto::rpc::AccountLogCursor {
                block_num: 0,
                transaction_index: 0,
                log_index: 64,
            }),
            ..valid.clone()
        },
        proto::rpc::GetAccountLogsRequest {
            after: Some(proto::rpc::AccountLogCursor {
                block_num: 0,
                transaction_index: 65536,
                log_index: 0,
            }),
            ..valid.clone()
        },
        proto::rpc::GetAccountLogsRequest {
            after: Some(proto::rpc::AccountLogCursor {
                block_num: 1,
                transaction_index: 0,
                log_index: 0,
            }),
            ..valid.clone()
        },
        proto::rpc::GetAccountLogsRequest {
            block_range: Some(proto::rpc::BlockRange { block_from: 1, block_to: 0 }),
            ..valid.clone()
        },
        proto::rpc::GetAccountLogsRequest {
            block_range: Some(proto::rpc::BlockRange { block_from: 0, block_to: u32::MAX }),
            ..valid
        },
    ] {
        assert_eq!(
            rpc.get_account_logs(invalid).await.unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
    }
}
