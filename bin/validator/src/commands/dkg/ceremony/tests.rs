use std::num::NonZeroUsize;
use std::sync::Arc;

use iroh::address_lookup::memory::MemoryLookup;
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointId, SecretKey as IrohSecretKey};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::{PublicKey, SigningKey};
use miden_protocol::utils::serde::Deserializable;
use miden_validator::{StorageKeyEpoch, ValidatorSigner};
use rand_core_06::OsRng;

use super::super::wire::WireCodec;
use super::ceremony_config::CeremonyConfig;
use super::session::{CeremonyNonce, SessionId};
use super::{Ceremony, ParticipantRegistry};

mod authentication;
mod configuration;
mod connections;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type TestResultWith<T> = Result<T, Box<dyn std::error::Error>>;

fn test_signing_key(seed: u8) -> SigningKey {
    SigningKey::read_from_bytes(&[seed; 32]).expect("test signing key must decode")
}

#[test]
fn ceremony_config_codec_roundtrip() {
    let expected =
        CeremonyConfig::new(&[SigningKey::new().public_key()], 1, StorageKeyEpoch::new([9; 32]));
    let encoded = expected.encode();
    let decoded = CeremonyConfig::decode(&encoded).unwrap();

    assert_eq!(decoded, expected);
}

fn test_ceremony(
    signing_key: &SigningKey,
    endpoint_secret: IrohSecretKey,
    peers: Vec<(EndpointId, PublicKey)>,
) -> Ceremony {
    let mut validator_set = vec![signing_key.public_key()];
    validator_set.extend(peers.iter().map(|(_, key)| key.clone()));
    Ceremony {
        validator_set,
        endpoint_secret,
        enable_public_relay: false,
        bind_address: Some("127.0.0.1:0".parse().unwrap()),
        peers: peers.into_iter().map(|(id, key)| (id, (id.into(), key))).collect(),
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
    let ceremony_a = test_ceremony(
        &signing_key_a,
        endpoint_secret_a,
        vec![(endpoint_b.id(), signing_key_b.public_key())],
    );
    let ceremony_b = test_ceremony(
        &signing_key_b,
        endpoint_secret_b,
        vec![(endpoint_a.id(), signing_key_a.public_key())],
    );

    let (peers_a, peers_b) = tokio::try_join!(
        ceremony_a.authenticate_peers(&endpoint_a),
        ceremony_b.authenticate_peers(&endpoint_b),
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
    let ceremony_a = test_ceremony(
        &signing_key_a,
        endpoint_secret_a,
        vec![(endpoint_b.id(), signing_key_b.public_key())],
    );
    let ceremony_b = test_ceremony(
        &signing_key_b,
        endpoint_secret_b,
        vec![(endpoint_a.id(), signing_key_a.public_key())],
    );

    let (peers_a, peers_b) = tokio::try_join!(
        ceremony_a.authenticate_peers(&endpoint_a),
        ceremony_b.authenticate_peers(&endpoint_b),
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
