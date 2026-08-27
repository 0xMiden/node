use std::collections::BTreeSet;
use std::sync::Arc;

use iroh::address_lookup::memory::MemoryLookup;
use iroh::endpoint::{Side, presets};
use iroh::{Endpoint, EndpointId, SecretKey as IrohSecretKey};
use miden_protocol::block::ValidatorKeys;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::{PublicKey, SigningKey};
use miden_protocol::crypto::hash::rpo::Rpo256;
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_validator::{StorageKeyEpoch, ValidatorSigner};
use rand_core_06::OsRng;

use super::{Challenge, Handshake, HandshakeMessage};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type TestResultWith<T> = Result<T, Box<dyn std::error::Error>>;

fn test_signing_key(seed: u8) -> SigningKey {
    SigningKey::read_from_bytes(&[seed; 32]).expect("test signing key must decode")
}

#[test]
fn handshake_codec_roundtrip() {
    let expected = HandshakeMessage {
        genesis_commitment: Rpo256::hash(b"test genesis"),
        threshold: 2,
        epoch: StorageKeyEpoch::new([9; 32]),
        validator_public_key: SigningKey::new().public_key(),
        challenge: Challenge::random(&mut OsRng),
    };
    let encoded = expected.to_bytes();
    let decoded = HandshakeMessage::read_from_bytes(&encoded).unwrap();

    assert_eq!(decoded, expected);
}

fn test_handshake(signing_key: &SigningKey, validator_keys: Vec<PublicKey>) -> Handshake {
    let validator_set =
        ValidatorKeys::new(validator_keys).expect("test validator set must be valid");
    Handshake::new(
        Rpo256::hash(b"test genesis"),
        2,
        StorageKeyEpoch::new([9; 32]),
        Challenge::random(&mut OsRng),
        validator_set,
        Arc::new(ValidatorSigner::new_local(signing_key.clone())),
    )
}

async fn bind_test_endpoint(secret_key: IrohSecretKey) -> TestResultWith<(Endpoint, MemoryLookup)> {
    let address_lookup = MemoryLookup::new();
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(secret_key)
        .alpns(vec![Handshake::ALPN.to_vec()])
        .address_lookup(address_lookup.clone())
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0")?
        .bind()
        .await?;
    Ok((endpoint, address_lookup))
}

#[tokio::test]
async fn three_validators_authenticate_their_endpoint_bindings() -> TestResult {
    let endpoint_secrets = [11u8, 12, 13].map(|seed| IrohSecretKey::from_bytes(&[seed; 32]));
    let (endpoint_a, lookup_a) = bind_test_endpoint(endpoint_secrets[0].clone()).await?;
    let (endpoint_b, lookup_b) = bind_test_endpoint(endpoint_secrets[1].clone()).await?;
    let (endpoint_c, lookup_c) = bind_test_endpoint(endpoint_secrets[2].clone()).await?;
    let endpoint_addrs = [endpoint_a.addr(), endpoint_b.addr(), endpoint_c.addr()];
    for lookup in [&lookup_a, &lookup_b, &lookup_c] {
        for endpoint_addr in endpoint_addrs.clone() {
            lookup.add_endpoint_info(endpoint_addr);
        }
    }

    let signing_keys = [21u8, 22, 23].map(test_signing_key);
    let validator_keys = signing_keys.iter().map(SigningKey::public_key).collect::<Vec<_>>();
    let endpoint_ids = [endpoint_a.id(), endpoint_b.id(), endpoint_c.id()];
    let peers = |local: EndpointId| {
        endpoint_ids
            .into_iter()
            .filter(|endpoint| *endpoint != local)
            .collect::<BTreeSet<_>>()
    };

    let authentication_for_a = test_handshake(&signing_keys[0], validator_keys.clone())
        .connect_and_authenticate_peers(endpoint_a.clone(), peers(endpoint_a.id()));
    let authentication_for_b = test_handshake(&signing_keys[1], validator_keys.clone())
        .connect_and_authenticate_peers(endpoint_b.clone(), peers(endpoint_b.id()));
    let authentication_for_c = test_handshake(&signing_keys[2], validator_keys)
        .connect_and_authenticate_peers(endpoint_c.clone(), peers(endpoint_c.id()));
    let (peers_seen_by_a, peers_seen_by_b, peers_seen_by_c) =
        tokio::try_join!(authentication_for_a, authentication_for_b, authentication_for_c,)?;

    for (local_index, authenticated) in
        [peers_seen_by_a, peers_seen_by_b, peers_seen_by_c].into_iter().enumerate()
    {
        let mut actual = authenticated
            .iter()
            .map(|peer| (peer.endpoint_id(), peer.validator_public_key.clone()))
            .collect::<Vec<_>>();
        actual.sort_by_key(|(endpoint_id, _)| *endpoint_id);
        let mut expected = endpoint_ids
            .into_iter()
            .zip(signing_keys.iter().map(SigningKey::public_key))
            .filter(|(endpoint_id, _)| *endpoint_id != endpoint_ids[local_index])
            .collect::<Vec<_>>();
        expected.sort_by_key(|(endpoint_id, _)| *endpoint_id);
        assert_eq!(actual, expected);
    }

    endpoint_a.close().await;
    endpoint_b.close().await;
    endpoint_c.close().await;
    Ok(())
}

#[tokio::test]
async fn lower_endpoint_id_dials_peer() -> TestResult {
    let (endpoint_a, lookup_a) = bind_test_endpoint(IrohSecretKey::from_bytes(&[14; 32])).await?;
    let (endpoint_b, lookup_b) = bind_test_endpoint(IrohSecretKey::from_bytes(&[15; 32])).await?;
    lookup_a.add_endpoint_info(endpoint_b.addr());
    lookup_b.add_endpoint_info(endpoint_a.addr());

    let signing_key_a = test_signing_key(24);
    let signing_key_b = test_signing_key(25);
    let validator_keys = vec![signing_key_a.public_key(), signing_key_b.public_key()];
    let authentication_for_a = test_handshake(&signing_key_a, validator_keys.clone())
        .connect_and_authenticate_peers(endpoint_a.clone(), BTreeSet::from([endpoint_b.id()]));
    let authentication_for_b = test_handshake(&signing_key_b, validator_keys)
        .connect_and_authenticate_peers(endpoint_b.clone(), BTreeSet::from([endpoint_a.id()]));

    let (peers_seen_by_a, peers_seen_by_b) =
        tokio::try_join!(authentication_for_a, authentication_for_b)?;
    assert_eq!(peers_seen_by_a.len(), 1);
    assert_eq!(peers_seen_by_b.len(), 1);

    let (lower_peer, higher_peer) = if endpoint_a.id() < endpoint_b.id() {
        (&peers_seen_by_a[0], &peers_seen_by_b[0])
    } else {
        (&peers_seen_by_b[0], &peers_seen_by_a[0])
    };
    assert_eq!(lower_peer.connection.side(), Side::Client);
    assert_eq!(higher_peer.connection.side(), Side::Server);

    endpoint_a.close().await;
    endpoint_b.close().await;
    Ok(())
}

#[tokio::test]
async fn handshake_rejects_validator_key_outside_genesis() -> TestResult {
    let (endpoint_a, lookup_a) = bind_test_endpoint(IrohSecretKey::from_bytes(&[14; 32])).await?;
    let (endpoint_b, lookup_b) = bind_test_endpoint(IrohSecretKey::from_bytes(&[15; 32])).await?;
    lookup_a.add_endpoint_info(endpoint_b.addr());
    lookup_b.add_endpoint_info(endpoint_a.addr());

    let signing_key_a = test_signing_key(24);
    let expected_signing_key_b = test_signing_key(25);
    let outsider_signing_key = test_signing_key(26);
    let authentication_for_a = test_handshake(
        &signing_key_a,
        vec![signing_key_a.public_key(), expected_signing_key_b.public_key()],
    )
    .connect_and_authenticate_peers(endpoint_a.clone(), BTreeSet::from([endpoint_b.id()]));
    let authentication_for_outsider = test_handshake(
        &outsider_signing_key,
        vec![signing_key_a.public_key(), outsider_signing_key.public_key()],
    )
    .connect_and_authenticate_peers(endpoint_b.clone(), BTreeSet::from([endpoint_a.id()]));

    let (result_a, _) = tokio::join!(authentication_for_a, authentication_for_outsider);
    let error = result_a.err().expect("validator A should reject the outsider");
    assert!(format!("{error:#}").contains("authenticated validator set does not match genesis"));

    endpoint_a.close().await;
    endpoint_b.close().await;
    Ok(())
}

#[tokio::test]
async fn handshake_rejects_signature_from_different_domain() -> TestResult {
    let (endpoint_a, lookup_a) = bind_test_endpoint(IrohSecretKey::from_bytes(&[16; 32])).await?;
    let (endpoint_b, lookup_b) = bind_test_endpoint(IrohSecretKey::from_bytes(&[17; 32])).await?;
    let (local_endpoint, local_lookup, peer_endpoint) = if endpoint_a.id() < endpoint_b.id() {
        (&endpoint_a, &lookup_a, &endpoint_b)
    } else {
        (&endpoint_b, &lookup_b, &endpoint_a)
    };
    local_lookup.add_endpoint_info(peer_endpoint.addr());

    let local_signing_key = test_signing_key(27);
    let peer_signing_key = test_signing_key(28);
    let authentication = test_handshake(
        &local_signing_key,
        vec![local_signing_key.public_key(), peer_signing_key.public_key()],
    )
    .connect_and_authenticate_peers(local_endpoint.clone(), BTreeSet::from([peer_endpoint.id()]));
    let respond_from_different_domain = async {
        let incoming = peer_endpoint
            .accept()
            .await
            .expect("peer should receive the handshake connection");
        let connection = incoming.accept()?.await?;
        let (mut send, mut receive) = connection.accept_bi().await?;

        let mut challenge_bytes = [0; super::HANDSHAKE_MESSAGE_BYTES];
        receive.read_exact(&mut challenge_bytes).await?;
        let request = HandshakeMessage::read_from_bytes(&challenge_bytes)?;
        let response = HandshakeMessage {
            genesis_commitment: Rpo256::hash(b"test genesis"),
            threshold: 2,
            epoch: StorageKeyEpoch::new([9; 32]),
            validator_public_key: peer_signing_key.public_key(),
            challenge: Challenge::random(&mut OsRng),
        };
        let mut commitment = b"different-protocol-domain".to_vec();
        commitment.extend_from_slice(&request.challenge.to_bytes());
        let signature = peer_signing_key.sign(Rpo256::hash(&commitment));
        send.write_all(&response.to_bytes()).await?;
        send.write_all(&signature.to_bytes()).await?;
        send.finish()?;
        let _ = connection.closed().await;
        Ok::<_, Box<dyn std::error::Error>>(())
    };

    let (authentication, response) = tokio::join!(authentication, respond_from_different_domain);
    response?;
    let error = authentication.err().expect("different signature domain should be rejected");
    assert!(format!("{error:#}").contains("peer handshake signature is invalid"));

    endpoint_a.close().await;
    endpoint_b.close().await;
    Ok(())
}

#[test]
fn handshake_signature_commits_to_challenge() {
    let first = HandshakeMessage {
        genesis_commitment: Rpo256::hash(b"test genesis"),
        threshold: 2,
        epoch: StorageKeyEpoch::new([9; 32]),
        validator_public_key: SigningKey::new().public_key(),
        challenge: Challenge::random(&mut OsRng),
    };
    let mut second = first.clone();
    second.challenge = Challenge::random(&mut OsRng);

    assert_ne!(first.challenge.commitment(), second.challenge.commitment());
}

#[test]
fn handshake_requires_matching_storage_key_epoch() {
    let signing_key = test_signing_key(71);
    let local = HandshakeMessage {
        genesis_commitment: Rpo256::hash(b"test genesis"),
        threshold: 2,
        epoch: StorageKeyEpoch::new([9; 32]),
        validator_public_key: signing_key.public_key(),
        challenge: Challenge::random(&mut OsRng),
    };
    let mut peer = local.clone();
    peer.epoch = StorageKeyEpoch::new([10; 32]);

    let error = local.validate_peer_configuration(&peer).unwrap_err();
    assert!(format!("{error:#}").contains("peer storage key epoch does not match"));
}
