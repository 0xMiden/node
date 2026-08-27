use std::collections::BTreeSet;
use std::sync::Arc;

use iroh::address_lookup::memory::MemoryLookup;
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointId, SecretKey as IrohSecretKey};
use miden_protocol::block::ValidatorKeys;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::{PublicKey, SigningKey};
use miden_protocol::crypto::hash::rpo::Rpo256;
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_validator::{StorageKeyEpoch, ValidatorSigner};

use super::{CeremonyNonce, Handshake, HandshakeMessage, HandshakeTranscript};

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
        nonce: CeremonyNonce([2; 32]),
    };
    let encoded = expected.to_bytes();
    let decoded = HandshakeMessage::read_from_bytes(&encoded).unwrap();

    assert_eq!(decoded, expected);
}

fn test_handshake(
    signing_key: &SigningKey,
    validator_keys: Vec<PublicKey>,
    nonce: u8,
) -> Handshake {
    let validator_set =
        ValidatorKeys::new(validator_keys).expect("test validator set must be valid");
    Handshake::new(
        Rpo256::hash(b"test genesis"),
        2,
        StorageKeyEpoch::new([9; 32]),
        CeremonyNonce([nonce; 32]),
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

    let authentication_for_a = test_handshake(&signing_keys[0], validator_keys.clone(), 31)
        .connect_and_authenticate_peers(endpoint_a.clone(), peers(endpoint_a.id()));
    let authentication_for_b = test_handshake(&signing_keys[1], validator_keys.clone(), 32)
        .connect_and_authenticate_peers(endpoint_b.clone(), peers(endpoint_b.id()));
    let authentication_for_c = test_handshake(&signing_keys[2], validator_keys, 33)
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
        34,
    )
    .connect_and_authenticate_peers(endpoint_a.clone(), BTreeSet::from([endpoint_b.id()]));
    let authentication_for_outsider = test_handshake(
        &outsider_signing_key,
        vec![signing_key_a.public_key(), outsider_signing_key.public_key()],
        35,
    )
    .connect_and_authenticate_peers(endpoint_b.clone(), BTreeSet::from([endpoint_a.id()]));

    let (result_a, _) = tokio::join!(authentication_for_a, authentication_for_outsider);
    let error = result_a.err().expect("validator A should reject the outsider");
    assert!(format!("{error:#}").contains("authenticated validator set does not match genesis"));

    endpoint_a.close().await;
    endpoint_b.close().await;
    Ok(())
}

#[test]
fn handshake_commits_to_dialer_endpoint() {
    let dialer_signing_key = test_signing_key(41);
    let acceptor_signing_key = test_signing_key(42);
    let dialer_endpoint = IrohSecretKey::from_bytes(&[51; 32]).public();
    let acceptor_endpoint = IrohSecretKey::from_bytes(&[52; 32]).public();
    let dialer_message = HandshakeMessage {
        genesis_commitment: Rpo256::hash(b"test genesis"),
        threshold: 2,
        epoch: StorageKeyEpoch::new([9; 32]),
        validator_public_key: dialer_signing_key.public_key(),
        nonce: CeremonyNonce([61; 32]),
    };
    let acceptor_message = HandshakeMessage {
        genesis_commitment: Rpo256::hash(b"test genesis"),
        threshold: 2,
        epoch: StorageKeyEpoch::new([9; 32]),
        validator_public_key: acceptor_signing_key.public_key(),
        nonce: CeremonyNonce([62; 32]),
    };
    let commitment = HandshakeTranscript {
        dialer_endpoint,
        dialer_message: dialer_message.clone(),
        acceptor_endpoint,
        acceptor_message: acceptor_message.clone(),
    }
    .signature_commitment();

    let substituted_endpoint = IrohSecretKey::from_bytes(&[53; 32]).public();
    let substituted_commitment = HandshakeTranscript {
        dialer_endpoint: substituted_endpoint,
        dialer_message,
        acceptor_endpoint,
        acceptor_message,
    }
    .signature_commitment();
    assert_ne!(commitment, substituted_commitment);
}

#[test]
fn handshake_commits_to_acceptor_endpoint() {
    let dialer_signing_key = test_signing_key(41);
    let acceptor_signing_key = test_signing_key(42);
    let dialer_endpoint = IrohSecretKey::from_bytes(&[51; 32]).public();
    let acceptor_endpoint = IrohSecretKey::from_bytes(&[52; 32]).public();
    let dialer_message = HandshakeMessage {
        genesis_commitment: Rpo256::hash(b"test genesis"),
        threshold: 2,
        epoch: StorageKeyEpoch::new([9; 32]),
        validator_public_key: dialer_signing_key.public_key(),
        nonce: CeremonyNonce([61; 32]),
    };
    let acceptor_message = HandshakeMessage {
        genesis_commitment: Rpo256::hash(b"test genesis"),
        threshold: 2,
        epoch: StorageKeyEpoch::new([9; 32]),
        validator_public_key: acceptor_signing_key.public_key(),
        nonce: CeremonyNonce([62; 32]),
    };
    let commitment = HandshakeTranscript {
        dialer_endpoint,
        dialer_message: dialer_message.clone(),
        acceptor_endpoint,
        acceptor_message: acceptor_message.clone(),
    }
    .signature_commitment();

    let substituted_endpoint = IrohSecretKey::from_bytes(&[53; 32]).public();
    let substituted_commitment = HandshakeTranscript {
        dialer_endpoint,
        dialer_message,
        acceptor_endpoint: substituted_endpoint,
        acceptor_message,
    }
    .signature_commitment();
    assert_ne!(commitment, substituted_commitment);
}

#[test]
fn handshake_requires_matching_storage_key_epoch() {
    let signing_key = test_signing_key(71);
    let local = HandshakeMessage {
        genesis_commitment: Rpo256::hash(b"test genesis"),
        threshold: 2,
        epoch: StorageKeyEpoch::new([9; 32]),
        validator_public_key: signing_key.public_key(),
        nonce: CeremonyNonce([72; 32]),
    };
    let mut peer = local.clone();
    peer.epoch = StorageKeyEpoch::new([10; 32]);

    let error = local.validate_peer_configuration(&peer).unwrap_err();
    assert!(format!("{error:#}").contains("peer storage key epoch does not match"));
}
