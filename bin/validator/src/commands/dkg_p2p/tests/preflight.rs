use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use iroh::{EndpointId, SecretKey as IrohSecretKey};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey;
use miden_protocol::utils::serde::Serializable;

use super::super::super::ValidatorSigningKey;
use super::super::ParticipateOptions;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type TestResultWith<T> = Result<T, Box<dyn std::error::Error>>;

struct TestGenesis {
    path: PathBuf,
    signing_keys: Vec<SigningKey>,
}

fn write_genesis(root: &Path, validator_count: usize) -> TestResultWith<TestGenesis> {
    let signing_keys = (0..validator_count).map(|_| SigningKey::new()).collect::<Vec<_>>();
    let validator_keys = signing_keys.iter().map(SigningKey::public_key).collect();
    let config = concat!(
        "version = 1\n",
        "timestamp = 1717344256\n",
        "\n[fee_parameters]\n",
        "verification_base_fee = 0\n",
    );
    let config_path = root.join("genesis.toml");
    fs_err::write(&config_path, config)?;
    let genesis_directory = root.join("genesis");
    super::super::super::genesis::generate(
        &genesis_directory,
        &root.join("accounts"),
        Some(&config_path),
        validator_keys,
    )?;

    Ok(TestGenesis {
        path: genesis_directory.join("genesis.dat"),
        signing_keys,
    })
}

fn write_endpoint_secret(root: &Path, seed: u8) -> TestResultWith<(PathBuf, EndpointId)> {
    let secret = IrohSecretKey::from_bytes(&[seed; 32]);
    let path = root.join(format!("endpoint-{seed}.secret"));
    fs_err::write(&path, secret.to_bytes())?;
    Ok((path, secret.public()))
}

fn participate_options(
    genesis: &Path,
    signing_key: &SigningKey,
    endpoint_secret: &Path,
    peer_endpoints: Vec<EndpointId>,
    threshold: usize,
) -> ParticipateOptions {
    ParticipateOptions {
        genesis: genesis.to_path_buf(),
        endpoint_secret: endpoint_secret.to_path_buf(),
        peer_endpoints,
        threshold: NonZeroUsize::new(threshold).expect("test threshold must be nonzero"),
        epoch: "09".repeat(32),
        signing_key: ValidatorSigningKey {
            signing_key: Some(hex::encode(signing_key.to_bytes())),
            signing_key_kms_id: None,
        },
    }
}

#[tokio::test]
async fn participate_accepts_the_complete_offline_configuration() -> TestResult {
    let root = tempfile::tempdir()?;
    let genesis = write_genesis(root.path(), 3)?;
    let (endpoint_secret, _) = write_endpoint_secret(root.path(), 1)?;
    let (_, peer_one) = write_endpoint_secret(root.path(), 2)?;
    let (_, peer_two) = write_endpoint_secret(root.path(), 3)?;

    participate_options(
        &genesis.path,
        &genesis.signing_keys[0],
        &endpoint_secret,
        vec![peer_one, peer_two],
        2,
    )
    .validate()
    .await?;

    Ok(())
}

#[tokio::test]
async fn single_validator_ceremony_succeeds() -> TestResult {
    let root = tempfile::tempdir()?;
    let genesis = write_genesis(root.path(), 1)?;
    let (endpoint_secret, _) = write_endpoint_secret(root.path(), 1)?;

    participate_options(&genesis.path, &genesis.signing_keys[0], &endpoint_secret, Vec::new(), 1)
        .handle()
        .await?;

    Ok(())
}

#[tokio::test]
async fn participate_rejects_a_signer_outside_genesis() -> TestResult {
    let root = tempfile::tempdir()?;
    let genesis = write_genesis(root.path(), 3)?;
    let outsider = SigningKey::new();
    let (endpoint_secret, _) = write_endpoint_secret(root.path(), 1)?;
    let (_, peer_one) = write_endpoint_secret(root.path(), 2)?;
    let (_, peer_two) = write_endpoint_secret(root.path(), 3)?;

    let error = participate_options(
        &genesis.path,
        &outsider,
        &endpoint_secret,
        vec![peer_one, peer_two],
        2,
    )
    .validate()
    .await
    .err()
    .expect("validation should fail");

    assert!(format!("{error:#}").contains("validator signing key is not committed by genesis"));
    Ok(())
}

#[tokio::test]
async fn participate_rejects_an_invalid_peer_endpoint_set() -> TestResult {
    let root = tempfile::tempdir()?;
    let genesis = write_genesis(root.path(), 3)?;
    let (endpoint_secret, local_endpoint) = write_endpoint_secret(root.path(), 1)?;
    let (_, peer_one) = write_endpoint_secret(root.path(), 2)?;

    let cases = [
        (vec![peer_one], "expected 2 peer endpoints"),
        (vec![peer_one, peer_one], "peer endpoints contain duplicates"),
        (vec![peer_one, local_endpoint], "peer endpoints contain the local endpoint"),
    ];
    for (peer_endpoints, expected) in cases {
        let error = participate_options(
            &genesis.path,
            &genesis.signing_keys[0],
            &endpoint_secret,
            peer_endpoints,
            2,
        )
        .validate()
        .await
        .err()
        .expect("validation should fail");
        let error = format!("{error:#}");
        assert!(error.contains(expected), "expected {expected:?} in {error:?}");
    }
    Ok(())
}

#[tokio::test]
async fn participate_rejects_a_threshold_exceeding_the_genesis_validator_set() -> TestResult {
    let root = tempfile::tempdir()?;
    let genesis = write_genesis(root.path(), 3)?;
    let (endpoint_secret, _) = write_endpoint_secret(root.path(), 1)?;
    let (_, peer_one) = write_endpoint_secret(root.path(), 2)?;
    let (_, peer_two) = write_endpoint_secret(root.path(), 3)?;

    let error = participate_options(
        &genesis.path,
        &genesis.signing_keys[0],
        &endpoint_secret,
        vec![peer_one, peer_two],
        4,
    )
    .validate()
    .await
    .err()
    .expect("validation should fail");
    assert!(format!("{error:#}").contains("threshold must not exceed the 3 genesis validators"));

    Ok(())
}
