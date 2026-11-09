use miden_node_proto::{DecodeMessageExt, generated};
use miden_protocol::Word;
use miden_protocol::block::BlockBody;
use miden_protocol::block::code_tree::CodePatch;
use miden_protocol::testing::account_id::ACCOUNT_ID_PRIVATE_SENDER;
use miden_protocol::transaction::{
    InputNotes,
    OrderedTransactionHeaders,
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
    let body = BlockBody::new(vec![], vec![], vec![], groups.clone()).unwrap();
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
            vec![OrderedTransactionHeaders::new_unchecked(vec![])]
        )
        .is_err()
    );
}
