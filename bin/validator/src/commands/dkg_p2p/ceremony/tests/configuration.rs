use std::time::Duration;

use miden_protocol::Word;

use super::*;

#[rstest::rstest]
#[case::different_genesis(Rpo256::hash(b"other genesis"), 2, StorageKeyEpoch::new([9; 32]))]
#[case::different_threshold(Rpo256::hash(b"test genesis"), 1, StorageKeyEpoch::new([9; 32]))]
#[case::different_epoch(Rpo256::hash(b"test genesis"), 2, StorageKeyEpoch::new([10; 32]))]
#[tokio::test]
async fn config_exchange_rejects_mismatch(
    #[case] genesis_commitment: Word,
    #[case] threshold: usize,
    #[case] epoch: StorageKeyEpoch,
) -> TestResult {
    let secret_a = IrohSecretKey::generate();
    let secret_b = IrohSecretKey::generate();
    let (endpoint_a, lookup_a) = bind_test_endpoint(secret_a.clone()).await?;
    let (endpoint_b, lookup_b) = bind_test_endpoint(secret_b.clone()).await?;
    lookup_a.add_endpoint_info(endpoint_b.addr());
    lookup_b.add_endpoint_info(endpoint_a.addr());

    let signing_key_a = SigningKey::new();
    let signing_key_b = SigningKey::new();
    let validator_keys = vec![signing_key_a.public_key(), signing_key_b.public_key()];
    let ceremony_a = test_ceremony(
        &signing_key_a,
        validator_keys.clone(),
        secret_a,
        BTreeSet::from([endpoint_b.id()]),
    );
    let mut ceremony_b =
        test_ceremony(&signing_key_b, validator_keys, secret_b, BTreeSet::from([endpoint_a.id()]));
    ceremony_b.genesis_commitment = genesis_commitment;
    ceremony_b.threshold = NonZeroUsize::new(threshold).unwrap();
    ceremony_b.epoch = epoch;
    let config_a = format!("{:?}", ceremony_a.config()?);
    let config_b = format!("{:?}", ceremony_b.config()?);

    let (result_a, result_b) = tokio::time::timeout(Duration::from_secs(10), async {
        // Valid genesis identities authenticate even when their ceremony settings disagree.
        let (peers_a, peers_b) = tokio::try_join!(
            ceremony_a.authenticate_peers(&endpoint_a),
            ceremony_b.authenticate_peers(&endpoint_b),
        )?;
        Ok::<_, anyhow::Error>(tokio::join!(
            ceremony_a.exchange_configs(peers_a),
            ceremony_b.exchange_configs(peers_b),
        ))
    })
    .await??;
    let errors = [result_a, result_b].map(|result| {
        let error = result.err().expect("different ceremony configs must stop the exchange");
        format!("{error:#}")
    });
    // One validator's abort may disconnect the other before it compares configurations.
    assert!(
        errors.iter().any(|error| {
            error.contains("peer ceremony config does not match")
                && error.contains(&config_a)
                && error.contains(&config_b)
        }),
        "expected a configuration mismatch with both configurations, got {errors:?}",
    );

    endpoint_a.close().await;
    endpoint_b.close().await;
    Ok(())
}
