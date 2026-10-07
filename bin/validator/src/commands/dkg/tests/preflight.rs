use std::net::{Ipv4Addr, UdpSocket};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use clap::Parser;
use iroh::{EndpointId, SecretKey as IrohSecretKey};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::{PublicKey, SigningKey};
use miden_protocol::utils::serde::Serializable;

use super::super::super::{ValidatorCommand, ValidatorSigningKey, ValidatorStorageKey};
use super::super::{DkgCommand, ParticipateOptions};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type TestResultWith<T> = Result<T, Box<dyn std::error::Error>>;

fn write_endpoint_secret(root: &Path, seed: u8) -> TestResultWith<(PathBuf, EndpointId)> {
    let secret = IrohSecretKey::from_bytes(&[seed; 32]);
    let path = root.join(format!("endpoint-{seed}.secret"));
    fs_err::write(&path, secret.to_bytes())?;
    Ok((path, secret.public()))
}

impl ParticipateOptions {
    fn for_tests(
        output_file: &Path,
        signing_key: &SigningKey,
        endpoint_secret: &Path,
        peers: Vec<(PublicKey, EndpointId)>,
        threshold: usize,
    ) -> Self {
        Self {
            output_file: output_file.to_path_buf(),
            endpoint_secret: endpoint_secret.to_path_buf(),
            enable_public_relay: false,
            bind_address: Some("127.0.0.1:0".parse().unwrap()),
            peers: peers
                .into_iter()
                .flat_map(|(key, id)| [hex::encode(key.to_bytes()), format!("{id}@127.0.0.1:9")])
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
    let signing_key = SigningKey::new();
    let (endpoint_secret, _) = write_endpoint_secret(root.path(), 1)?;

    ParticipateOptions::for_tests(&output_file, &signing_key, &endpoint_secret, Vec::new(), 1)
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
    let signing_keys = (0..3).map(|_| SigningKey::new()).collect::<Vec<_>>();
    let endpoints = (1..=3)
        .map(|seed| write_endpoint_secret(root.path(), seed))
        .collect::<Result<Vec<_>, _>>()?;
    let sockets = (0..3)
        .map(|_| UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)))
        .collect::<Result<Vec<_>, _>>()?;
    let mut commands = Vec::new();
    let mut outputs = Vec::new();
    for local in 0..3 {
        let output = root.path().join(format!("{local}.bundle"));
        let mut args = vec![
            "miden-validator".to_owned(),
            "dkg".to_owned(),
            "participate".to_owned(),
            "--output-file".to_owned(),
            output.display().to_string(),
            "--endpoint-secret".to_owned(),
            endpoints[local].0.display().to_string(),
            "--signing-key.hex".to_owned(),
            hex::encode(signing_keys[local].to_bytes()),
            "--bind-address".to_owned(),
            sockets[local].local_addr()?.to_string(),
            "--threshold".to_owned(),
            "2".to_owned(),
            "--epoch".to_owned(),
            "09".repeat(32),
            "--timeout".to_owned(),
            "30s".to_owned(),
        ];
        // Rotate peer order to check that argument order does not change the shared result.
        for offset in 1..3 {
            let peer = (local + offset) % 3;
            args.extend([
                "--peer".to_owned(),
                hex::encode(signing_keys[peer].public_key().to_bytes()),
                format!("{}@{}", endpoints[peer].1, sockets[peer].local_addr()?),
            ]);
        }
        let ValidatorCommand::Dkg(options) = ValidatorCommand::try_parse_from(args)? else {
            panic!("expected DKG command");
        };
        let DkgCommand::Participate(options) = options.command else {
            panic!("expected participate command");
        };
        commands.push(options);
        outputs.push(output);
    }
    drop(sockets);
    futures::future::try_join_all(commands.into_iter().map(|options| options.handle())).await?;
    let bundles = outputs
        .into_iter()
        .map(|file| ValidatorStorageKey { file }.load())
        .collect::<Result<Vec<_>, _>>()?;
    for pair in bundles.windows(2) {
        assert_eq!(pair[0].setup_context(), pair[1].setup_context());
        assert_eq!(pair[0].public_key_set(), pair[1].public_key_set());
        assert_ne!(pair[0].participant(), pair[1].participant());
    }
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
    let signing_keys = (0..2).map(|_| SigningKey::new()).collect::<Vec<_>>();
    let (endpoint_secret, _) = write_endpoint_secret(root.path(), 1)?;
    let mut options = ParticipateOptions::for_tests(
        &root.path().join("operator-key.bundle"),
        &signing_keys[0],
        &endpoint_secret,
        Vec::new(),
        1,
    );
    options.enable_public_relay = enable_public_relay;
    options.peers = vec![
        hex::encode(signing_keys[1].public_key().to_bytes()),
        IrohSecretKey::generate().public().to_string(),
    ];

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
    let signing_key = SigningKey::new();
    let (endpoint_secret, _) = write_endpoint_secret(root.path(), 1)?;
    ParticipateOptions::for_tests(&output_file, &signing_key, &endpoint_secret, Vec::new(), 1)
        .handle()
        .await?;

    let original = fs_err::read(&output_file)?;
    let mut options =
        ParticipateOptions::for_tests(&output_file, &signing_key, &endpoint_secret, Vec::new(), 1);
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
    let signing_keys = (0..2).map(|_| SigningKey::new()).collect::<Vec<_>>();
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
        &signing_keys[0],
        &endpoint_secret,
        vec![(signing_keys[1].public_key(), peer)],
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

#[rstest::rstest]
#[case::local_key(true)]
#[case::duplicate_peer_key(false)]
#[tokio::test]
async fn participate_rejects_repeated_validator_keys(#[case] local_key: bool) -> TestResult {
    let root = tempfile::tempdir()?;
    let signing_keys = (0..3).map(|_| SigningKey::new()).collect::<Vec<_>>();
    let (endpoint_secret, _) = write_endpoint_secret(root.path(), 1)?;
    let (_, peer_one) = write_endpoint_secret(root.path(), 2)?;
    let (_, peer_two) = write_endpoint_secret(root.path(), 3)?;

    let error = ParticipateOptions::for_tests(
        &root.path().join("operator-key.bundle"),
        &signing_keys[0],
        &endpoint_secret,
        vec![
            (signing_keys[1].public_key(), peer_one),
            (signing_keys[usize::from(!local_key)].public_key(), peer_two),
        ],
        2,
    )
    .validate()
    .await
    .err()
    .expect("validation should fail");

    let expected = if local_key {
        "peer keys contain the local validator key"
    } else {
        "peer validator keys contain duplicates"
    };
    assert!(format!("{error:#}").contains(expected), "{error:#}");
    Ok(())
}

#[tokio::test]
async fn participate_rejects_an_invalid_peer_endpoint_set() -> TestResult {
    let root = tempfile::tempdir()?;
    let signing_keys = (0..3).map(|_| SigningKey::new()).collect::<Vec<_>>();
    let (endpoint_secret, local_endpoint) = write_endpoint_secret(root.path(), 1)?;
    let (_, peer_one) = write_endpoint_secret(root.path(), 2)?;

    let cases = [
        (vec![peer_one, peer_one], "peer endpoints contain duplicates"),
        (vec![peer_one, local_endpoint], "peer endpoints contain the local endpoint"),
    ];
    for (peer_endpoints, expected) in cases {
        let mut options = ParticipateOptions::for_tests(
            &root.path().join("operator-key.bundle"),
            &signing_keys[0],
            &endpoint_secret,
            signing_keys[1..]
                .iter()
                .map(SigningKey::public_key)
                .zip(peer_endpoints)
                .collect(),
            2,
        );
        // Distinct socket addresses must not make duplicate endpoint identities acceptable.
        for (index, pair) in options.peers.as_chunks_mut::<2>().0.iter_mut().enumerate() {
            let id = ParticipateOptions::parse_peer_endpoint(&pair[1])?.id;
            pair[1] = format!("{id}@127.0.0.1:{}", 9000 + index);
        }
        let error = options.validate().await.err().expect("validation should fail");
        let error = format!("{error:#}");
        assert!(error.contains(expected), "expected {expected:?} in {error:?}");
    }
    Ok(())
}

#[tokio::test]
async fn participate_rejects_a_threshold_exceeding_the_validator_set() -> TestResult {
    let root = tempfile::tempdir()?;
    let signing_keys = (0..3).map(|_| SigningKey::new()).collect::<Vec<_>>();
    let (endpoint_secret, _) = write_endpoint_secret(root.path(), 1)?;
    let (_, peer_one) = write_endpoint_secret(root.path(), 2)?;
    let (_, peer_two) = write_endpoint_secret(root.path(), 3)?;

    let error = ParticipateOptions::for_tests(
        &root.path().join("operator-key.bundle"),
        &signing_keys[0],
        &endpoint_secret,
        vec![
            (signing_keys[1].public_key(), peer_one),
            (signing_keys[2].public_key(), peer_two),
        ],
        4,
    )
    .validate()
    .await
    .err()
    .expect("validation should fail");
    assert!(format!("{error:#}").contains("threshold must not exceed the 3 configured validators"));

    Ok(())
}
