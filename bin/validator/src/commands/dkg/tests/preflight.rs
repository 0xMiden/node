use std::net::{Ipv4Addr, UdpSocket};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use iroh::{EndpointAddr, EndpointId, SecretKey as IrohSecretKey};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey;
use miden_protocol::utils::serde::Serializable;

use super::super::super::{ValidatorSigningKey, ValidatorStorageKey};
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
    let genesis_directory = root.join("genesis");
    super::super::super::genesis::tests::command(root, validator_keys)?.execute()?;

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

impl ParticipateOptions {
    fn for_tests(
        output_file: &Path,
        genesis: &Path,
        signing_key: &SigningKey,
        endpoint_secret: &Path,
        peer_endpoints: Vec<EndpointId>,
        threshold: usize,
    ) -> Self {
        Self {
            output_file: output_file.to_path_buf(),
            genesis: genesis.to_path_buf(),
            endpoint_secret: endpoint_secret.to_path_buf(),
            enable_public_relay: false,
            bind_address: Some("127.0.0.1:0".parse().unwrap()),
            peer_endpoints: peer_endpoints
                .into_iter()
                .map(|id| EndpointAddr::new(id).with_ip_addr("127.0.0.1:9".parse().unwrap()))
                .collect(),
            timeout: Duration::from_secs(30),
            threshold: NonZeroUsize::new(threshold).expect("test threshold must be nonzero"),
            epoch: "09".repeat(32),
            signing_key: ValidatorSigningKey {
                signing_key: Some(hex::encode(signing_key.to_bytes())),
                signing_key_kms_id: None,
            },
        }
    }
}

#[tokio::test]
async fn single_validator_ceremony_succeeds() -> TestResult {
    let root = tempfile::tempdir()?;
    let output_file = root.path().join("operator-key.bundle");
    let genesis = write_genesis(root.path(), 1)?;
    let (endpoint_secret, _) = write_endpoint_secret(root.path(), 1)?;

    ParticipateOptions::for_tests(
        &output_file,
        &genesis.path,
        &genesis.signing_keys[0],
        &endpoint_secret,
        Vec::new(),
        1,
    )
    .handle()
    .await?;

    let operator_key = ValidatorStorageKey { file: output_file.clone() }.load()?;
    assert_eq!(operator_key.key_epoch().as_bytes(), &[9; 32]);
    assert_eq!(operator_key.participant().get(), 1);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs_err::metadata(output_file)?.permissions().mode() & 0o777, 0o600,);
    }

    Ok(())
}

#[tokio::test]
async fn ceremony_succeeds_without_public_infrastructure() -> TestResult {
    let root = tempfile::tempdir()?;
    let genesis = write_genesis(root.path(), 2)?;
    let (secret_a, endpoint_a) = write_endpoint_secret(root.path(), 1)?;
    let (secret_b, endpoint_b) = write_endpoint_secret(root.path(), 2)?;
    let output_a = root.path().join("a.bundle");
    let output_b = root.path().join("b.bundle");
    let socket_a = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    let socket_b = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    let address_a = socket_a.local_addr()?;
    let address_b = socket_b.local_addr()?;
    let mut options_a = ParticipateOptions::for_tests(
        &output_a,
        &genesis.path,
        &genesis.signing_keys[0],
        &secret_a,
        vec![endpoint_b],
        2,
    );
    let mut options_b = ParticipateOptions::for_tests(
        &output_b,
        &genesis.path,
        &genesis.signing_keys[1],
        &secret_b,
        vec![endpoint_a],
        2,
    );
    options_a.bind_address = Some(address_a);
    options_b.bind_address = Some(address_b);
    options_a.peer_endpoints =
        vec![ParticipateOptions::parse_peer_endpoint(&format!("{endpoint_b}@{address_b}"))?];
    options_b.peer_endpoints =
        vec![ParticipateOptions::parse_peer_endpoint(&format!("{endpoint_a}@{address_a}"))?];
    drop((socket_a, socket_b));

    tokio::try_join!(options_a.handle(), options_b.handle())?;

    let key_a = ValidatorStorageKey { file: output_a }.load()?;
    let key_b = ValidatorStorageKey { file: output_b }.load()?;
    assert_eq!(key_a.setup_context(), key_b.setup_context());
    assert_eq!(key_a.public_key_set(), key_b.public_key_set());
    assert_ne!(key_a.participant(), key_b.participant());
    Ok(())
}

#[rstest::rstest]
#[case::direct_only(false)]
#[case::public_relay(true)]
#[tokio::test]
async fn peer_socket_is_required_without_public_relay(
    #[case] enable_public_relay: bool,
) -> TestResult {
    let root = tempfile::tempdir()?;
    let genesis = write_genesis(root.path(), 2)?;
    let (endpoint_secret, _) = write_endpoint_secret(root.path(), 1)?;
    let mut options = ParticipateOptions::for_tests(
        &root.path().join("operator-key.bundle"),
        &genesis.path,
        &genesis.signing_keys[0],
        &endpoint_secret,
        Vec::new(),
        1,
    );
    options.enable_public_relay = enable_public_relay;
    options.peer_endpoints = vec![IrohSecretKey::generate().public().into()];

    let result = options.validate().await;
    if enable_public_relay {
        result?;
    } else {
        let error = result.err().expect("ID-only peers require public discovery");
        assert!(
            error
                .to_string()
                .contains("requires a socket address unless --enable-public-relay is set")
        );
    }
    Ok(())
}

#[rstest::rstest]
#[case::id_only("")]
#[case::ipv4("@127.0.0.1:9000")]
#[case::ipv6("@[::1]:9000")]
fn peer_endpoint_parses_optional_socket(#[case] suffix: &str) -> TestResult {
    let id = IrohSecretKey::generate().public();
    let peer = ParticipateOptions::parse_peer_endpoint(&format!("{id}{suffix}"))?;
    assert_eq!(peer.id, id);
    let expected = suffix.strip_prefix('@').map(str::parse).transpose()?;
    assert_eq!(
        peer.ip_addrs().copied().collect::<Vec<_>>(),
        expected.into_iter().collect::<Vec<_>>()
    );
    Ok(())
}

#[rstest::rstest]
#[case::empty("")]
#[case::zero_port("127.0.0.1:0")]
#[case::unspecified("0.0.0.0:9000")]
#[case::multicast("224.0.0.1:9000")]
fn peer_endpoint_rejects_unusable_socket(#[case] socket: &str) {
    let id = IrohSecretKey::generate().public();
    assert!(ParticipateOptions::parse_peer_endpoint(&format!("{id}@{socket}")).is_err());
}

#[tokio::test]
async fn ceremony_refuses_to_overwrite_bundle() -> TestResult {
    let root = tempfile::tempdir()?;
    let output_file = root.path().join("operator-key.bundle");
    let genesis = write_genesis(root.path(), 1)?;
    let (endpoint_secret, _) = write_endpoint_secret(root.path(), 1)?;
    ParticipateOptions::for_tests(
        &output_file,
        &genesis.path,
        &genesis.signing_keys[0],
        &endpoint_secret,
        Vec::new(),
        1,
    )
    .handle()
    .await?;

    let original = fs_err::read(&output_file)?;
    let mut options = ParticipateOptions::for_tests(
        &output_file,
        &genesis.path,
        &genesis.signing_keys[0],
        &endpoint_secret,
        Vec::new(),
        1,
    );
    options.epoch = "0a".repeat(32);
    let error = options.handle().await.expect_err("existing storage keys must not be replaced");
    assert!(error.to_string().contains("storage key bundle already exists"));
    assert_eq!(fs_err::read(output_file)?, original, "bundle was modified");
    Ok(())
}

#[rstest::rstest]
#[case::dialer(true)]
#[case::acceptor(false)]
#[tokio::test]
async fn ceremony_times_out_waiting_for_a_peer(#[case] local_is_dialer: bool) -> TestResult {
    let root = tempfile::tempdir()?;
    let output_file = root.path().join("operator-key.bundle");
    let genesis = write_genesis(root.path(), 2)?;
    let (secret_a, endpoint_a) = write_endpoint_secret(root.path(), 1)?;
    let (secret_b, endpoint_b) = write_endpoint_secret(root.path(), 2)?;
    // Leave the peer offline for each connection direction.
    //
    // The ceremony timeout must stop both dialing and accepting connections.
    let (endpoint_secret, peer) = if (endpoint_a < endpoint_b) == local_is_dialer {
        (secret_a, endpoint_b)
    } else {
        (secret_b, endpoint_a)
    };
    let mut options = ParticipateOptions::for_tests(
        &output_file,
        &genesis.path,
        &genesis.signing_keys[0],
        &endpoint_secret,
        vec![peer],
        2,
    );
    options.timeout = Duration::from_millis(100);

    let started = Instant::now();
    let error = tokio::time::timeout(Duration::from_secs(5), options.handle())
        .await?
        .expect_err("a missing peer must not keep the ceremony running indefinitely");
    assert!(started.elapsed() >= Duration::from_millis(100));
    assert_eq!(error.to_string(), "DKG ceremony timed out after 100ms");
    assert!(!output_file.exists());
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

    let error = ParticipateOptions::for_tests(
        &root.path().join("operator-key.bundle"),
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
        let mut options = ParticipateOptions::for_tests(
            &root.path().join("operator-key.bundle"),
            &genesis.path,
            &genesis.signing_keys[0],
            &endpoint_secret,
            peer_endpoints,
            2,
        );
        // Distinct socket addresses must not make duplicate endpoint identities acceptable.
        for (index, peer) in options.peer_endpoints.iter_mut().enumerate() {
            *peer = EndpointAddr::new(peer.id)
                .with_ip_addr((Ipv4Addr::LOCALHOST, 9000 + index as u16).into());
        }
        let error = options.validate().await.err().expect("validation should fail");
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

    let error = ParticipateOptions::for_tests(
        &root.path().join("operator-key.bundle"),
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
