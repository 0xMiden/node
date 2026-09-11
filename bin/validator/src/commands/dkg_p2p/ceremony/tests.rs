use std::collections::BTreeSet;
use std::num::NonZeroUsize;
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

use super::super::wire::WireCodec;
use super::ceremony_config::CeremonyConfig;
use super::challenge::Challenge;
use super::session::{CeremonyNonce, SessionId};
use super::{Ceremony, ParticipantRegistry};

mod authentication;
mod configuration;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type TestResultWith<T> = Result<T, Box<dyn std::error::Error>>;

fn test_signing_key(seed: u8) -> SigningKey {
    SigningKey::read_from_bytes(&[seed; 32]).expect("test signing key must decode")
}

#[test]
fn ceremony_config_codec_roundtrip() {
    let expected =
        CeremonyConfig::new(Rpo256::hash(b"test genesis"), 2, StorageKeyEpoch::new([9; 32]));
    let encoded = expected.encode();
    let decoded = CeremonyConfig::decode(&encoded).unwrap();

    assert_eq!(decoded, expected);
}

fn test_ceremony(
    signing_key: &SigningKey,
    validator_keys: Vec<PublicKey>,
    endpoint_secret: IrohSecretKey,
    peer_endpoints: BTreeSet<EndpointId>,
) -> Ceremony {
    let validator_set =
        ValidatorKeys::new(validator_keys).expect("test validator set must be valid");
    Ceremony {
        genesis_commitment: Rpo256::hash(b"test genesis"),
        validator_set: Arc::new(validator_set),
        endpoint_secret,
        peer_endpoints,
        threshold: NonZeroUsize::new(2).unwrap(),
        epoch: StorageKeyEpoch::new([9; 32]),
        signer: Arc::new(ValidatorSigner::new_local(signing_key.clone())),
    }
}

async fn bind_test_endpoint(secret_key: IrohSecretKey) -> TestResultWith<(Endpoint, MemoryLookup)> {
    let address_lookup = MemoryLookup::new();
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(secret_key)
        .alpns(vec![Ceremony::ALPN.to_vec()])
        .address_lookup(address_lookup.clone())
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0")?
        .bind()
        .await?;
    Ok((endpoint, address_lookup))
}

#[tokio::test]
async fn registry_confirmation_rejects_different_registry_roots() -> TestResult {
    let endpoint_secret_a = IrohSecretKey::from_bytes(&[31; 32]);
    let endpoint_secret_b = IrohSecretKey::from_bytes(&[32; 32]);
    let (endpoint_a, lookup_a) = bind_test_endpoint(endpoint_secret_a.clone()).await?;
    let (endpoint_b, lookup_b) = bind_test_endpoint(endpoint_secret_b.clone()).await?;
    lookup_a.add_endpoint_info(endpoint_b.addr());
    lookup_b.add_endpoint_info(endpoint_a.addr());

    let signing_key_a = test_signing_key(33);
    let signing_key_b = test_signing_key(34);
    let validator_keys = vec![signing_key_a.public_key(), signing_key_b.public_key()];
    let ceremony_a = test_ceremony(
        &signing_key_a,
        validator_keys.clone(),
        endpoint_secret_a,
        BTreeSet::from([endpoint_b.id()]),
    );
    let ceremony_b = test_ceremony(
        &signing_key_b,
        validator_keys,
        endpoint_secret_b,
        BTreeSet::from([endpoint_a.id()]),
    );

    let (peers_a, peers_b) = tokio::try_join!(
        ceremony_a.authenticate_peers_on(&endpoint_a),
        ceremony_b.authenticate_peers_on(&endpoint_b),
    )?;
    let (peers_a, peers_b) = tokio::try_join!(
        ceremony_a.exchange_configs(peers_a),
        ceremony_b.exchange_configs(peers_b),
    )?;
    let (session_a, session_b) = tokio::try_join!(
        ceremony_a.exchange_nonces(peers_a),
        ceremony_b.exchange_nonces(peers_b),
    )?;
    let (session_a, session_b) = tokio::try_join!(
        ceremony_a.confirm_session(session_a),
        ceremony_b.confirm_session(session_b),
    )?;
    let (participants_a, mut participants_b) = tokio::try_join!(
        ceremony_a.exchange_dkg_public_keys(session_a),
        ceremony_b.exchange_dkg_public_keys(session_b),
    )?;

    let mut entries = participants_b
        .registry
        .entries()
        .map(|(index, public_key)| (index, *public_key))
        .collect::<Vec<_>>();
    let first_public_key = entries[0].1;
    entries[0].1 = entries[1].1;
    entries[1].1 = first_public_key;
    participants_b.registry = ParticipantRegistry::new(entries)?;

    let (result_a, result_b) = tokio::join!(
        ceremony_a.confirm_dkg_registry(participants_a),
        ceremony_b.confirm_dkg_registry(participants_b),
    );
    for result in [result_a, result_b] {
        let error = result.err().expect("different DKG registry roots must be rejected");
        assert!(format!("{error:#}").contains("built a different DKG registry"));
    }

    endpoint_a.close().await;
    endpoint_b.close().await;
    Ok(())
}

#[tokio::test]
async fn session_confirmation_rejects_different_session_ids() -> TestResult {
    let endpoint_secret_a = IrohSecretKey::from_bytes(&[18; 32]);
    let endpoint_secret_b = IrohSecretKey::from_bytes(&[19; 32]);
    let (endpoint_a, lookup_a) = bind_test_endpoint(endpoint_secret_a.clone()).await?;
    let (endpoint_b, lookup_b) = bind_test_endpoint(endpoint_secret_b.clone()).await?;
    lookup_a.add_endpoint_info(endpoint_b.addr());
    lookup_b.add_endpoint_info(endpoint_a.addr());

    let signing_key_a = test_signing_key(29);
    let signing_key_b = test_signing_key(30);
    let validator_keys = vec![signing_key_a.public_key(), signing_key_b.public_key()];
    let ceremony_a = test_ceremony(
        &signing_key_a,
        validator_keys.clone(),
        endpoint_secret_a,
        BTreeSet::from([endpoint_b.id()]),
    );
    let ceremony_b = test_ceremony(
        &signing_key_b,
        validator_keys,
        endpoint_secret_b,
        BTreeSet::from([endpoint_a.id()]),
    );

    let (peers_a, peers_b) = tokio::try_join!(
        ceremony_a.authenticate_peers_on(&endpoint_a),
        ceremony_b.authenticate_peers_on(&endpoint_b),
    )?;
    let (peers_a, peers_b) = tokio::try_join!(
        ceremony_a.exchange_configs(peers_a),
        ceremony_b.exchange_configs(peers_b),
    )?;
    let (session_a, mut session_b) = tokio::try_join!(
        ceremony_a.exchange_nonces(peers_a),
        ceremony_b.exchange_nonces(peers_b),
    )?;
    assert_eq!(session_a.id, session_b.id);

    session_b.id = SessionId::derive(
        &ceremony_b.config()?,
        vec![
            (signing_key_a.public_key(), CeremonyNonce::random(&mut OsRng)),
            (signing_key_b.public_key(), CeremonyNonce::random(&mut OsRng)),
        ],
    );
    assert_ne!(session_a.id, session_b.id);

    let (result_a, result_b) =
        tokio::join!(ceremony_a.confirm_session(session_a), ceremony_b.confirm_session(session_b),);
    let errors = [result_a, result_b].map(|result| {
        let error = result.err().expect("different session IDs must be rejected");
        format!("{error:#}")
    });
    assert!(
        errors.iter().any(|error| error.contains("derived a different session ID")),
        "expected a session ID mismatch in {errors:?}",
    );

    endpoint_a.close().await;
    endpoint_b.close().await;
    Ok(())
}

#[tokio::test]
async fn lower_endpoint_id_dials_peer() -> TestResult {
    let endpoint_secret_a = IrohSecretKey::from_bytes(&[14; 32]);
    let endpoint_secret_b = IrohSecretKey::from_bytes(&[15; 32]);
    let (endpoint_a, lookup_a) = bind_test_endpoint(endpoint_secret_a.clone()).await?;
    let (endpoint_b, lookup_b) = bind_test_endpoint(endpoint_secret_b.clone()).await?;
    lookup_a.add_endpoint_info(endpoint_b.addr());
    lookup_b.add_endpoint_info(endpoint_a.addr());

    let signing_key_a = test_signing_key(24);
    let signing_key_b = test_signing_key(25);
    let validator_keys = vec![signing_key_a.public_key(), signing_key_b.public_key()];
    let ceremony_a = test_ceremony(
        &signing_key_a,
        validator_keys.clone(),
        endpoint_secret_a,
        BTreeSet::from([endpoint_b.id()]),
    );
    let ceremony_b = test_ceremony(
        &signing_key_b,
        validator_keys,
        endpoint_secret_b,
        BTreeSet::from([endpoint_a.id()]),
    );
    let authentication_for_a = ceremony_a.authenticate_peers_on(&endpoint_a);
    let authentication_for_b = ceremony_b.authenticate_peers_on(&endpoint_b);

    let (peers_a, peers_b) = tokio::try_join!(authentication_for_a, authentication_for_b)?;
    assert_eq!(peers_a.authenticated_peers.len(), 1);
    assert_eq!(peers_b.authenticated_peers.len(), 1);

    let (lower_peer, higher_peer) = if endpoint_a.id() < endpoint_b.id() {
        (&peers_a.authenticated_peers[0], &peers_b.authenticated_peers[0])
    } else {
        (&peers_b.authenticated_peers[0], &peers_a.authenticated_peers[0])
    };
    assert_eq!(lower_peer.connection().side(), Side::Client);
    assert_eq!(higher_peer.connection().side(), Side::Server);

    endpoint_a.close().await;
    endpoint_b.close().await;
    Ok(())
}

#[tokio::test]
async fn authentication_rejects_validator_key_outside_genesis() -> TestResult {
    let endpoint_secret_a = IrohSecretKey::from_bytes(&[14; 32]);
    let endpoint_secret_b = IrohSecretKey::from_bytes(&[15; 32]);
    let (endpoint_a, lookup_a) = bind_test_endpoint(endpoint_secret_a.clone()).await?;
    let (endpoint_b, lookup_b) = bind_test_endpoint(endpoint_secret_b.clone()).await?;
    lookup_a.add_endpoint_info(endpoint_b.addr());
    lookup_b.add_endpoint_info(endpoint_a.addr());

    let signing_key_a = test_signing_key(24);
    let expected_signing_key_b = test_signing_key(25);
    let outsider_signing_key = test_signing_key(26);
    let ceremony_a = test_ceremony(
        &signing_key_a,
        vec![signing_key_a.public_key(), expected_signing_key_b.public_key()],
        endpoint_secret_a,
        BTreeSet::from([endpoint_b.id()]),
    );
    let outsider_ceremony = test_ceremony(
        &outsider_signing_key,
        vec![signing_key_a.public_key(), outsider_signing_key.public_key()],
        endpoint_secret_b,
        BTreeSet::from([endpoint_a.id()]),
    );
    let authentication_for_a = ceremony_a.authenticate_peers_on(&endpoint_a);
    let authentication_for_outsider = outsider_ceremony.authenticate_peers_on(&endpoint_b);

    let (result_a, _) = tokio::join!(authentication_for_a, authentication_for_outsider);
    let error = result_a.err().expect("validator A should reject the outsider");
    assert!(format!("{error:#}").contains("peer validator key is not committed by genesis"));

    endpoint_a.close().await;
    endpoint_b.close().await;
    Ok(())
}

#[tokio::test]
async fn authentication_rejects_signature_from_different_domain() -> TestResult {
    let endpoint_secret_a = IrohSecretKey::from_bytes(&[16; 32]);
    let endpoint_secret_b = IrohSecretKey::from_bytes(&[17; 32]);
    let (endpoint_a, lookup_a) = bind_test_endpoint(endpoint_secret_a.clone()).await?;
    let (endpoint_b, lookup_b) = bind_test_endpoint(endpoint_secret_b.clone()).await?;
    let (local_endpoint, local_lookup, local_endpoint_secret, peer_endpoint) =
        if endpoint_a.id() < endpoint_b.id() {
            (&endpoint_a, &lookup_a, endpoint_secret_a, &endpoint_b)
        } else {
            (&endpoint_b, &lookup_b, endpoint_secret_b, &endpoint_a)
        };
    local_lookup.add_endpoint_info(peer_endpoint.addr());

    let local_signing_key = test_signing_key(27);
    let peer_signing_key = test_signing_key(28);
    let ceremony = test_ceremony(
        &local_signing_key,
        vec![local_signing_key.public_key(), peer_signing_key.public_key()],
        local_endpoint_secret,
        BTreeSet::from([peer_endpoint.id()]),
    );
    let authentication = ceremony.authenticate_peers_on(local_endpoint);
    let respond_from_different_domain = async {
        let incoming = peer_endpoint
            .accept()
            .await
            .expect("peer should receive the authentication connection");
        let connection = incoming.accept()?.await?;
        let (mut send, mut receive) = connection.accept_bi().await?;

        let mut challenge_bytes = [0; Challenge::BYTES];
        receive.read_exact(&mut challenge_bytes).await?;
        let challenge = Challenge::decode(&challenge_bytes)?;
        let peer_challenge = Challenge::random(&mut OsRng);
        send.write_all(&peer_challenge.encode()).await?;

        let mut commitment = b"different-protocol-domain".to_vec();
        commitment.extend_from_slice(&challenge.encode());
        let signature = peer_signing_key.sign(Rpo256::hash(&commitment));
        send.write_all(&peer_signing_key.public_key().to_bytes()).await?;
        send.write_all(&signature.to_bytes()).await?;
        send.finish()?;
        let _ = connection.closed().await;
        Ok::<_, Box<dyn std::error::Error>>(())
    };

    let (authentication, response) = tokio::join!(authentication, respond_from_different_domain);
    response?;
    let error = authentication.err().expect("different signature domain should be rejected");
    assert!(format!("{error:#}").contains("peer challenge response signature is invalid"));

    endpoint_a.close().await;
    endpoint_b.close().await;
    Ok(())
}

#[test]
fn authentication_signature_commits_to_challenge() {
    let first = Challenge::random(&mut OsRng);
    let second = Challenge::random(&mut OsRng);

    assert_ne!(first.commitment(), second.commitment());
}
