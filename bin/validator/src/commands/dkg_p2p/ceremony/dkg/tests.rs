use std::collections::BTreeSet;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use golden_core::verify_dealing_for_receiver;
use golden_ehtdh1::{Combiner, UnsealingShare};
use golden_evrf::paper::secp_secq::SecpSecqBackend;
use iroh::address_lookup::memory::MemoryLookup;
use iroh::endpoint::presets;
use iroh::{Endpoint, SecretKey as IrohSecretKey};
use itertools::Itertools;
use miden_protocol::block::ValidatorKeys;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey;
use miden_protocol::crypto::hash::rpo::Rpo256;
use miden_validator::{StorageKeyEpoch, ValidatorSigner};
use tokio::task::JoinSet;

use super::super::peer::AuthenticatedPeer;
use super::*;

mod rejection;

struct TestCeremony {
    endpoints: Vec<Endpoint>,
    validators: Vec<(Ceremony, DkgParticipants, LocalDealings)>,
}

impl TestCeremony {
    async fn create_dealings(threshold: usize, validator_count: usize) -> anyhow::Result<Self> {
        let signing_keys = (0..validator_count).map(|_| SigningKey::new()).collect::<Vec<_>>();
        let validator_set = Arc::new(ValidatorKeys::new(
            signing_keys.iter().map(SigningKey::public_key).collect(),
        )?);
        let mut endpoints = Vec::new();
        let mut endpoint_secrets = Vec::new();
        let mut lookups = Vec::new();
        for _ in 0..validator_count {
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
                threshold: NonZeroUsize::new(threshold).unwrap(),
                epoch: StorageKeyEpoch::new([9; 32]),
                signer: Arc::new(ValidatorSigner::new_local(signing_key)),
            };
            exchanges.spawn(async move {
                let peers = ceremony.authenticate_peers(&endpoint).await?;
                let peers = ceremony.exchange_configs(peers).await?;
                let session = ceremony.exchange_nonces(peers).await?;
                let session = ceremony.confirm_session(session).await?;
                let participants = ceremony.exchange_dkg_public_keys(session).await?;
                let participants = ceremony.confirm_dkg_registry(participants).await?;
                let dealings = ceremony.create_dealings(&participants)?;
                Ok::<_, anyhow::Error>((ceremony, participants, dealings))
            });
        }
        let mut validators = Vec::new();
        tokio::time::timeout(Duration::from_secs(30), async {
            while let Some(result) = exchanges.join_next().await {
                validators.push(result??);
            }
            Ok::<_, anyhow::Error>(())
        })
        .await??;
        Ok(Self { endpoints, validators })
    }
}

#[rstest::rstest]
#[case::one_of_one(1, 1)]
#[case::one_of_two(1, 2)]
#[case::two_of_two(2, 2)]
#[case::one_of_three(1, 3)]
#[case::two_of_three(2, 3)]
#[case::three_of_three(3, 3)]
#[tokio::test]
async fn ceremony_succeeds(
    #[case] threshold: usize,
    #[case] validator_count: usize,
) -> anyhow::Result<()> {
    let TestCeremony { endpoints, validators } =
        TestCeremony::create_dealings(threshold, validator_count).await?;
    let mut confirmations = JoinSet::new();
    for (ceremony, mut participants, dealings) in validators {
        confirmations.spawn(async move {
            let dealings = ceremony.exchange_dealings(&mut participants, dealings).await?;
            let dealings = ceremony.confirm_dealings(&mut participants, dealings).await?;
            // Keep connections alive until every validator finishes confirmation.
            Ok::<_, anyhow::Error>((ceremony, participants, dealings))
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
    let expected = confirmed[0].2.commitment();
    let mut outputs = Vec::new();
    let mut streams = Vec::new();
    for (ceremony, mut participants, dealings) in confirmed {
        assert_eq!(dealings.commitment(), expected);
        assert_eq!(dealings.decryption_dealing_count(), validator_count);
        assert_eq!(dealings.context_dealing_count(), validator_count);
        let output = ceremony.complete_dkg(&participants, dealings)?;
        assert_eq!(output.secret_share.participant, participants.local_index);
        assert_eq!(output.setup_context.epoch, *ceremony.epoch.as_bytes());
        outputs.push(output);
        participants.finish_streams()?;
        streams.extend(
            participants
                .session
                .authenticated_peers
                .into_iter()
                .map(AuthenticatedPeer::into_streams),
        );
    }

    tokio::time::timeout(Duration::from_secs(10), async {
        for (_, send, receive) in &mut streams {
            // All ceremony messages used the first stream, which is now finished in both
            // directions.
            assert_eq!(send.id().index(), 0);
            assert_eq!(receive.id(), send.id());
            assert_eq!(receive.read(&mut [0]).await?, None);
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    for output in &outputs {
        assert_eq!(output.sealing_key, outputs[0].sealing_key);
        assert_eq!(output.public_key_set, outputs[0].public_key_set);
        assert_eq!(output.setup_context, outputs[0].setup_context);
    }

    let plaintext = b"private record encrypted with the P2P ceremony's public key";
    let ciphertext = outputs[0].sealing_key.seal_bytes(&mut OsRng, plaintext)?;
    let decryption_context = b"test record access";
    let combiner =
        Combiner::new(outputs[0].public_key_set.clone(), outputs[0].setup_context.clone())?;
    let shares = outputs
        .into_iter()
        .map(|output| {
            UnsealingShare::new(output.secret_share).decrypt_share(
                &mut OsRng,
                &output.setup_context,
                &ciphertext,
                decryption_context,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    for selected in shares.into_iter().combinations(threshold) {
        assert_eq!(combiner.combine_exact(&ciphertext, decryption_context, &selected)?, plaintext,);
    }
    for endpoint in endpoints {
        endpoint.close().await;
    }
    Ok(())
}

#[tokio::test]
async fn dealing_confirmation_rejects_different_valid_dealings() -> anyhow::Result<()> {
    for round in ["decryption", "context"] {
        let TestCeremony { endpoints, validators } = TestCeremony::create_dealings(2, 3).await?;
        let mut exchanges = JoinSet::new();
        for (ceremony, mut participants, dealings) in validators {
            exchanges.spawn(async move {
                let dealings = ceremony.exchange_dealings(&mut participants, dealings).await?;
                Ok::<_, anyhow::Error>((ceremony, participants, dealings))
            });
        }
        let mut validators = tokio::time::timeout(Duration::from_secs(10), async {
            let mut validators = Vec::new();
            while let Some(result) = exchanges.join_next().await {
                validators.push(result??);
            }
            Ok::<_, anyhow::Error>(validators)
        })
        .await??;
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
        for (ceremony, mut participants, dealings) in validators {
            confirmations
                .spawn(async move { ceremony.confirm_dealings(&mut participants, dealings).await });
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
