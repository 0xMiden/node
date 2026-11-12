use miden_node_proto::DecodeMessageExt;
use miden_node_proto::domain::transaction_logs::{
    GetTransactionLogsRequest,
    GetTransactionLogsResponse,
};
use miden_node_proto::generated::miden::node::v1::{
    GetTransactionLogsRequest as ProtoRequest,
    GetTransactionLogsResponse as ProtoResponse,
};
use miden_node_proto::generated::transaction::transaction_log_details::Visibility;
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1;
use miden_protocol::transaction::{LogTopic, TransactionId, TransactionLog};

fn account() -> AccountId {
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1.try_into().unwrap()
}

#[test]
fn transaction_log_request_requires_valid_account_and_transaction_id() {
    let id = TransactionId::from_raw(Word::from([1_u32; 4]));
    let valid = ProtoRequest {
        native_account_id: Some(account().into()),
        transaction_id: Some(id.into()),
    };
    let decoded: GetTransactionLogsRequest = valid.clone().decode_and_verify().unwrap();
    assert_eq!(decoded.native_account_id, account());
    assert_eq!(decoded.transaction_id, id);
    let mut invalid = valid.clone();
    invalid.native_account_id = None;
    assert!(invalid.decode_and_verify().is_err());
    let mut invalid = valid.clone();
    invalid.transaction_id = None;
    assert!(invalid.decode_and_verify().is_err());
    let mut invalid = valid.clone();
    invalid.native_account_id.as_mut().unwrap().version = None;
    assert!(invalid.decode_and_verify().is_err());
    let mut invalid = valid;
    invalid.transaction_id.as_mut().unwrap().id.as_mut().unwrap().encoded = vec![0; 31];
    assert!(invalid.decode_and_verify().is_err());
}

#[test]
fn transaction_log_response_preserves_public_private_and_empty_presence() {
    let log =
        TransactionLog::new(account(), LogTopic::new(1_u32.into(), 2_u32.into()), vec![]).unwrap();
    for logs in [None, Some(vec![]), Some(vec![log.clone(), log.clone()])] {
        let stored = Word::from([42_u32; 4]);
        let wire = ProtoResponse::from(GetTransactionLogsResponse {
            native_account_id: account(),
            transaction_id: TransactionId::from_raw(Word::empty()),
            block_num: BlockNumber::ONE,
            transaction_index: 7,
            logs_commitment: stored,
            logs: logs.clone(),
        });
        assert_eq!(wire.logs_commitment, Some(stored.into()));
        assert_eq!(wire.native_account_id, Some(account().into()));
        assert_eq!(wire.block_num, 1);
        assert_eq!(wire.transaction_index, 7);
        match (logs, wire.log_details.unwrap().visibility.unwrap()) {
            (None, Visibility::Private(commitment)) => assert_eq!(commitment, stored.into()),
            (Some(expected), Visibility::Public(actual)) => {
                assert_eq!(actual.logs, expected.iter().map(Into::into).collect::<Vec<_>>());
            },
            _ => panic!("visibility changed"),
        }
    }
}
