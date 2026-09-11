use std::collections::BTreeSet;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use golden_core::verify_dealing_for_receiver;
use golden_evrf::paper::secp_secq::SecpSecqBackend;
use iroh::address_lookup::memory::MemoryLookup;
use iroh::endpoint::presets;
use iroh::{Endpoint, SecretKey as IrohSecretKey};
use miden_protocol::block::ValidatorKeys;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey;
use miden_validator::{StorageKeyEpoch, ValidatorSigner};

use super::*;

struct TestCeremony {
    endpoints: Vec<Endpoint>,
    validators: Vec<(Ceremony, DkgParticipants, UnconfirmedDkgDealings)>,
}

impl TestCeremony {
    async fn exchange_dealings() -> anyhow::Result<Self> {
        let signing_keys = [SigningKey::new(), SigningKey::new(), SigningKey::new()];
        let validator_set = Arc::new(ValidatorKeys::new(
            signing_keys.iter().map(SigningKey::public_key).collect(),
        )?);
        let mut endpoints = Vec::new();
        let mut endpoint_secrets = Vec::new();
        let mut lookups = Vec::new();
        for _ in 0..3 {
            let secret = IrohSecretKey::generate();
            let lookup = MemoryLookup::new();
            let endpoint = Endpoint::builder(presets::Minimal)
                .secret_key(secret.clone())
                .alpns(vec![Ceremony::ALPN.to_vec()])
                .address_lookup(lookup.clone())
                .clear_ip_transports()
                .bind_addr("127.0.0.1:0")?
                .bind()
                .await?;
            endpoints.push(endpoint);
            endpoint_secrets.push(secret);
            lookups.push(lookup);
        }
        for lookup in &lookups {
            for endpoint in &endpoints {
                lookup.add_endpoint_info(endpoint.addr());
            }
        }

        let endpoint_ids = endpoints.iter().map(Endpoint::id).collect::<BTreeSet<_>>();
        let mut exchanges = JoinSet::new();
        for ((signing_key, endpoint_secret), endpoint) in
            signing_keys.into_iter().zip(endpoint_secrets).zip(endpoints.clone())
        {
            let mut peer_endpoints = endpoint_ids.clone();
            peer_endpoints.remove(&endpoint.id());
            let ceremony = Ceremony {
                genesis_commitment: Rpo256::hash(b"test genesis"),
                validator_set: Arc::clone(&validator_set),
                endpoint_secret,
                peer_endpoints,
                threshold: NonZeroUsize::new(2).unwrap(),
                epoch: StorageKeyEpoch::new([9; 32]),
                signer: Arc::new(ValidatorSigner::new_local(signing_key)),
            };
            exchanges.spawn(async move {
                let peers = ceremony.authenticate_peers_on(&endpoint).await?;
                let peers = ceremony.exchange_configs(peers).await?;
                let session = ceremony.exchange_nonces(peers).await?;
                let session = ceremony.confirm_session(session).await?;
                let participants = ceremony.exchange_dkg_public_keys(session).await?;
                let participants = ceremony.confirm_dkg_registry(participants).await?;
                let dealings = ceremony.create_dealings(&participants)?;
                let dealings = ceremony.exchange_dealings(&participants, dealings).await?;
                Ok::<_, anyhow::Error>((ceremony, participants, dealings))
            });
        }
        let mut validators = Vec::new();
        while let Some(result) = exchanges.join_next().await {
            validators.push(result??);
        }
        Ok(Self { endpoints, validators })
    }
}

#[tokio::test]
async fn three_validators_confirm_the_same_dealings() -> anyhow::Result<()> {
    let TestCeremony { endpoints, validators } = TestCeremony::exchange_dealings().await?;
    let (_, participants, dealings) = &validators[0];
    let expected = DkgDealingsCommitment::from_dealings(participants, dealings);
    let mut confirmations = JoinSet::new();
    for (ceremony, participants, dealings) in validators {
        // Each validator inserts its own dealing separately from the arriving peer dealings.
        assert_eq!(DkgDealingsCommitment::from_dealings(&participants, &dealings), expected);
        confirmations.spawn(async move {
            let dealings = ceremony.confirm_dealings(&participants, dealings).await?;
            // Keep connections alive until every validator finishes confirmation.
            Ok::<_, anyhow::Error>((participants, dealings))
        });
    }
    let confirmed = tokio::time::timeout(Duration::from_secs(10), async {
        let mut confirmed = Vec::new();
        while let Some(result) = confirmations.join_next().await {
            confirmed.push(result??);
        }
        Ok::<_, anyhow::Error>(confirmed)
    })
    .await??;
    for (_, dealings) in confirmed {
        assert_eq!(dealings.commitment(), expected);
        assert_eq!(dealings.decryption_dealing_count(), 3);
        assert_eq!(dealings.context_dealing_count(), 3);
    }
    for endpoint in endpoints {
        endpoint.close().await;
    }
    Ok(())
}

#[tokio::test]
async fn dealing_confirmation_rejects_different_valid_dealings() -> anyhow::Result<()> {
    for round in ["decryption", "context"] {
        let TestCeremony { endpoints, mut validators } = TestCeremony::exchange_dealings().await?;
        let (dealer_ceremony, dealer, _) = &validators[2];
        let alternate = dealer_ceremony.create_dealings(dealer)?;
        let dealer_index = dealer.local_index;
        let (_, receiver, dealings) = &mut validators[0];
        let (message, config, peer_dealings) = match round {
            "decryption" => (
                alternate.decryption_dealing.message,
                &dealings.local.decryption_config,
                &mut dealings.peer_decryption_dealings,
            ),
            "context" => (
                alternate.context_dealing.message,
                &dealings.local.context_config,
                &mut dealings.peer_context_dealings,
            ),
            _ => unreachable!(),
        };
        // Model the dealer sending a different, valid contribution to just one receiver.
        verify_dealing_for_receiver::<StorageGroup, SecpSecqBackend>(
            receiver.local_index,
            &receiver.secret_key.0,
            &message,
            config,
        )?;
        peer_dealings.insert(dealer_index, message);

        let mut confirmations = JoinSet::new();
        for (ceremony, participants, dealings) in validators {
            confirmations
                .spawn(async move { ceremony.confirm_dealings(&participants, dealings).await });
        }
        let errors = tokio::time::timeout(Duration::from_secs(10), async {
            let mut errors = Vec::new();
            while let Some(result) = confirmations.join_next().await {
                let error = result?.err().expect("different dealings must be rejected");
                errors.push(format!("{error:#}"));
            }
            Ok::<_, anyhow::Error>(errors)
        })
        .await??;
        // Aborting on a mismatch can disconnect other peers before their comparison finishes.
        assert!(
            errors.iter().any(|error| error.contains("received different DKG dealings")),
            "expected a {round} dealing mismatch: {errors:?}",
        );
        for endpoint in endpoints {
            endpoint.close().await;
        }
    }
    Ok(())
}
