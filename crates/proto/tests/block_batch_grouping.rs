use miden_node_proto::generated::blockchain::BlockBody as ProtoBlockBody;
use miden_node_proto::{DecodeMessageExt, generated};
use miden_protocol::Word;
use miden_protocol::block::BlockBody;
use miden_protocol::block::code_tree::CodePatch;
use miden_protocol::testing::account_id::ACCOUNT_ID_PRIVATE_SENDER;
use miden_protocol::transaction::{
    InputNotes,
    OrderedTransactionHeaders,
    PublicTransactionLogs,
    TransactionHeader,
    TransactionLogs,
};
use prost::Message;

#[test]
fn block_transport_preserves_batch_boundaries_and_order() {
    let groups: Vec<_> = [1_u32, 2]
        .into_iter()
        .map(|seed| {
            let header = TransactionHeader::new(
                ACCOUNT_ID_PRIVATE_SENDER.try_into().unwrap(),
                Word::from([seed; 4]),
                Word::from([seed + 1; 4]),
                InputNotes::default(),
                vec![],
                TransactionLogs::default().commitment(),
                CodePatch::default().commitment(),
            )
            .unwrap();
            OrderedTransactionHeaders::new_unchecked(vec![header])
        })
        .collect();
    let body =
        BlockBody::new(vec![], vec![], vec![], groups.clone(), PublicTransactionLogs::default())
            .unwrap();
    let bytes = generated::blockchain::BlockBody::from(&body).encode_to_vec();
    let decoded = generated::blockchain::BlockBody::decode(bytes.as_slice())
        .unwrap()
        .decode_and_build_unchecked()
        .unwrap();
    assert_eq!(decoded.transactions(), groups);
    assert_eq!(decoded.batch_ids().collect::<Vec<_>>(), body.batch_ids().collect::<Vec<_>>());
    assert_eq!(decoded.compute_batches_commitment(), body.compute_batches_commitment());
    assert_eq!(
        decoded.compute_transactions_commitment(),
        body.compute_transactions_commitment()
    );
    assert!(
        BlockBody::new(
            vec![],
            vec![],
            vec![],
            vec![OrderedTransactionHeaders::new_unchecked(vec![])],
            PublicTransactionLogs::default(),
        )
        .is_err()
    );
}

#[test]
fn block_transport_preserves_complete_public_logs() {
    use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1;
    use miden_protocol::transaction::{LogTopic, PublicTransactionLogs, TransactionLog};

    let native = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1.try_into().unwrap();
    let emitter = ACCOUNT_ID_PRIVATE_SENDER.try_into().unwrap();
    let log =
        TransactionLog::new(emitter, LogTopic::new(1_u32.into(), 2_u32.into()), vec![]).unwrap();
    let logs = TransactionLogs::new(vec![log.clone(), log]).unwrap();
    let headers: Vec<_> = [emitter, native]
        .into_iter()
        .enumerate()
        .map(|(index, account)| {
            TransactionHeader::new(
                account,
                Word::from([1_u32; 4]),
                Word::from([2_u32; 4]),
                InputNotes::default(),
                vec![],
                if index == 0 { Word::empty() } else { logs.commitment() },
                CodePatch::default().commitment(),
            )
            .unwrap()
        })
        .collect();
    let public =
        PublicTransactionLogs::new(vec![(headers[1].id(), logs.clone())], headers.iter()).unwrap();
    let body = BlockBody::new(
        vec![],
        vec![],
        vec![],
        vec![OrderedTransactionHeaders::new_unchecked(headers)],
        public,
    )
    .unwrap();
    let encoded = ProtoBlockBody::from(&body);
    let decoded = encoded.clone().decode_and_build_unchecked().unwrap();
    assert_eq!(decoded, body);
    assert_eq!(decoded.public_logs().entries()[0].1, logs);
    let mut missing = encoded;
    missing.public_logs = None;
    assert!(missing.decode_and_build_unchecked().is_err());
}
