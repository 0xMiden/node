use super::*;
use crate::commands::dkg_p2p::ceremony::session::{CeremonyNonce, SessionId};

#[derive(Clone, Copy, Debug)]
enum Round {
    Decryption,
    Context,
}

#[derive(Clone, Copy, Debug)]
enum InvalidDealing {
    WrongDealer,
    PreviousSession,
    CorruptedProof,
    CorruptedEncryptedShare,
}

#[rstest::rstest]
#[case::decryption_wrong_dealer(Round::Decryption, InvalidDealing::WrongDealer)]
#[case::context_wrong_dealer(Round::Context, InvalidDealing::WrongDealer)]
#[case::decryption_previous_session(Round::Decryption, InvalidDealing::PreviousSession)]
#[case::context_previous_session(Round::Context, InvalidDealing::PreviousSession)]
#[case::decryption_corrupted_proof(Round::Decryption, InvalidDealing::CorruptedProof)]
#[case::context_corrupted_proof(Round::Context, InvalidDealing::CorruptedProof)]
#[case::decryption_corrupted_share(Round::Decryption, InvalidDealing::CorruptedEncryptedShare)]
#[case::context_corrupted_share(Round::Context, InvalidDealing::CorruptedEncryptedShare)]
#[tokio::test]
async fn dealing_exchange_rejects_invalid_dealing(
    #[case] round: Round,
    #[case] invalid: InvalidDealing,
) -> anyhow::Result<()> {
    let TestCeremony { endpoints, mut validators } = TestCeremony::create_dealings(2, 2).await?;
    let (receiver_ceremony, mut receiver, receiver_dealings) = validators.pop().unwrap();
    let (sender_ceremony, mut sender, sender_dealings) = validators.pop().unwrap();
    let mut messages = DealerMessages::from_local(&sender_dealings);
    let (message, round_name) = match round {
        Round::Decryption => (&mut messages.decryption, "decryption"),
        Round::Context => (&mut messages.context, "context"),
    };
    match invalid {
        InvalidDealing::WrongDealer => {
            // Forward a genuine contribution, but not the authenticated sender's own.
            *message = match round {
                Round::Decryption => receiver_dealings.decryption_dealing.message.clone(),
                Round::Context => receiver_dealings.context_dealing.message.clone(),
            };
        },
        InvalidDealing::PreviousSession => {
            let current_session = sender.session.id;
            sender.session.id = SessionId::derive(
                &sender_ceremony.config()?,
                sender_ceremony
                    .validator_set
                    .as_keys()
                    .iter()
                    .cloned()
                    .map(|key| (key, CeremonyNonce::random(&mut OsRng)))
                    .collect(),
            );
            assert_ne!(sender.session.id, current_session);
            // Keep the registry and DKG secret unchanged to isolate session binding.
            let previous = sender_ceremony.create_dealings(&sender)?;
            sender.session.id = current_session;
            *message = match round {
                Round::Decryption => previous.decryption_dealing.message,
                Round::Context => previous.context_dealing.message,
            };
        },
        InvalidDealing::CorruptedProof => {
            *message.proof.last_mut().expect("two-validator dealing must contain a proof") ^= 1;
        },
        InvalidDealing::CorruptedEncryptedShare => {
            let share = message.encrypted_shares.get_mut(&receiver.local_index).unwrap();
            share.encrypted_share = share.encrypted_share.add(&StorageScalar::one());
        },
    }

    let (received, sent) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            receiver_ceremony.exchange_dealings(&mut receiver, receiver_dealings),
            sender.session.authenticated_peers[0].exchange_dealer_messages(&messages),
        )
    })
    .await?;
    sent?;
    let error = received.err().expect("invalid dealing must stop the exchange");
    let error = format!("{error:#}");
    let expected = match invalid {
        InvalidDealing::WrongDealer => format!(
            "authenticated participant {} sent a {round_name} dealing for participant {}",
            sender.local_index.get(),
            receiver.local_index.get(),
        ),
        _ => format!("invalid {round_name} dealing from participant {}", sender.local_index.get()),
    };
    assert!(error.contains(&expected), "expected {expected:?}, got {error:?}");
    if matches!(invalid, InvalidDealing::PreviousSession) {
        assert!(error.contains("session mismatch"), "{error}");
    }

    for endpoint in endpoints {
        endpoint.close().await;
    }
    Ok(())
}

#[rstest::rstest]
#[case::disconnect(true)]
#[case::truncated_message(false)]
#[tokio::test]
async fn dealing_exchange_rejects_interrupted_message(
    #[case] disconnect: bool,
) -> anyhow::Result<()> {
    let TestCeremony { endpoints, mut validators } = TestCeremony::create_dealings(2, 2).await?;
    let (receiver_ceremony, mut receiver, receiver_dealings) = validators.pop().unwrap();
    let (_, mut sender, sender_dealings) = validators.pop().unwrap();
    let (connection, mut send, mut receive) =
        sender.session.authenticated_peers.pop().unwrap().into_streams();
    let message = DealerMessages::from_local(&sender_dealings).encode();
    let (received, sent) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(receiver_ceremony.exchange_dealings(&mut receiver, receiver_dealings), async {
            send.write_all(&message[..message.len() - 1]).await?;
            // Wait for the other side to enter the exchange before interrupting it.
            receive.read_exact(&mut vec![0; message.len()]).await?;
            if disconnect {
                connection.close(0u8.into(), b"interrupted dealing exchange");
            } else {
                send.finish()?;
            }
            Ok::<_, anyhow::Error>(())
        },)
    })
    .await?;
    sent?;
    let error = received.err().expect("an interrupted message must stop the exchange");
    let error = format!("{error:#}");
    assert!(error.contains("failed to read peer dealer messages"), "{error}");
    for endpoint in endpoints {
        endpoint.close().await;
    }
    Ok(())
}
