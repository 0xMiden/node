use std::time::Duration;

use miden_node_proto::generated::miden::node::v1::BlockSubscriptionResponse;
use miden_node_utils::shutdown::CancellationToken;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey;

use super::{
    BlockSignatures,
    PartialBlockchain,
    SignedBlock,
    ValidatorConfig,
    empty_block_at,
    random_secret_key,
    setup_db_with_validators,
};
use crate::server::validator_service::recovery::apply_stream;

#[tokio::test]
async fn catch_up_keeps_verified_prefix_and_resumes_across_quorum_change() {
    let keys: [SigningKey; 3] = [random_secret_key(), random_secret_key(), random_secret_key()];
    let config =
        |k| ValidatorConfig::new(keys.iter().map(SigningKey::public_key).collect(), k).unwrap();
    let (_dir, db, genesis, _) = setup_db_with_validators(config(2)).await;
    let mut chain = PartialBlockchain::default();
    let (first, body) = empty_block_at(&genesis, &chain, genesis.timestamp() + 1)
        .with_next_validator_config(config(3))
        .into_header_and_body()
        .unwrap();
    let signatures = |commitment, k| {
        BlockSignatures::new(keys[..k].iter().map(|key| key.sign(commitment)).collect()).unwrap()
    };
    let block = SignedBlock::new_unchecked(first.clone(), body, signatures(first.commitment(), 2));
    chain.add_block(&genesis, false);
    let (second, body) = empty_block_at(&first, &chain, first.timestamp() + 1)
        .into_header_and_body()
        .unwrap();
    let child = |k| {
        SignedBlock::new_unchecked(second.clone(), body.clone(), signatures(second.commitment(), k))
    };
    let event = |block: SignedBlock, tip| {
        Ok(BlockSubscriptionResponse {
            block: Some(block.into()),
            committed_chain_tip: tip,
            protocol_config: None,
        })
    };
    let stop = CancellationToken::new();
    let wait = Duration::from_secs(1);
    let stream = tokio_stream::iter([event(block, 2), event(child(2), 3)]);
    assert!(apply_stream(stream, &db, genesis, &stop, wait).await.is_err());
    assert_eq!(db.load_chain_tip().await.unwrap(), Some(first.clone()));

    // A growing remote tip cannot extend the target once a session starts.
    chain.add_block(&first, false);
    let (third, body) = empty_block_at(&second, &chain, second.timestamp() + 1)
        .into_header_and_body()
        .unwrap();
    let block = SignedBlock::new_unchecked(third.clone(), body, signatures(third.commitment(), 3));
    let stream = tokio_stream::iter([event(child(3), 3), event(block, 4)]);
    apply_stream(stream, &db, first, &stop, wait).await.unwrap();
    assert_eq!(db.load_chain_tip().await.unwrap(), Some(third));
}
