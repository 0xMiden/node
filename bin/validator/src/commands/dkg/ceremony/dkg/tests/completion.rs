use miden_protocol::crypto::hash::rpo::Rpo256;

use super::*;
use crate::commands::dkg::ceremony::session::{CeremonyNonce, SessionId};

#[derive(Clone, Copy)]
enum Mismatch {
    Session,
    Dealings,
    PublicKeySet,
    SetupContext,
}

#[rstest::rstest]
#[case::session(Mismatch::Session)]
#[case::dealings(Mismatch::Dealings)]
#[case::public_key_set(Mismatch::PublicKeySet)]
#[case::setup_context(Mismatch::SetupContext)]
#[tokio::test]
async fn completion_rejects_mismatch(#[case] mismatch: Mismatch) -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let mut network = TestCeremony::create_dealings(2, 2).await?;
    let mut validators = network.complete_dkg().await?;
    let mut local = validators.pop().unwrap();
    let mut peer = validators.pop().unwrap();
    local.ceremony.persist(&root.path().join("local.bundle"), local.output)?;
    peer.ceremony.persist(&root.path().join("peer.bundle"), peer.output.clone())?;

    let mut dealings_commitment = peer.dealings_commitment;
    match mismatch {
        Mismatch::Session => {
            peer.participants.session.id = SessionId::derive(
                &peer.ceremony.config()?,
                vec![(peer.ceremony.signer.public_key(), CeremonyNonce::random(&mut OsRng))],
            );
        },
        Mismatch::Dealings => {
            dealings_commitment =
                DkgDealingsCommitment::decode(&Rpo256::hash(b"different dealings").as_bytes())?;
        },
        Mismatch::PublicKeySet => {
            peer.output.public_key_set.joint_public_key =
                StorageGroup::mul_generator(&StorageScalar::one());
        },
        Mismatch::SetupContext => peer.output.setup_context.epoch[0] ^= 1,
    }
    let different = Completion::new(&peer.participants, dealings_commitment, &peer.output);
    assert_ne!(local.completion, different);
    let (local_result, peer_result) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            local.ceremony.confirm_completion(&mut local.participants, local.completion),
            peer.ceremony.confirm_completion(&mut peer.participants, different),
        )
    })
    .await?;
    for result in [local_result, peer_result] {
        let error = result.expect_err("different completions must not report success");
        assert!(format!("{error:#}").contains("reported a different ceremony completion"));
    }
    for endpoint in network.endpoints {
        endpoint.close().await;
    }
    Ok(())
}

#[tokio::test]
async fn completion_waits_for_peer_persistence() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let mut network = TestCeremony::create_dealings(2, 3).await?;
    let mut validators = network.complete_dkg().await?;
    let mut local = validators.pop().unwrap();
    let mut ready = validators.pop().unwrap();
    let mut peer = validators.pop().unwrap();
    local.ceremony.persist(&root.path().join("local.bundle"), local.output)?;
    ready.ceremony.persist(&root.path().join("ready.bundle"), ready.output)?;
    let completion = local.ceremony.confirm_completion(&mut local.participants, local.completion);
    let ready_completion =
        ready.ceremony.confirm_completion(&mut ready.participants, ready.completion);
    tokio::pin!(completion, ready_completion);
    let early_completion = async {
        tokio::select! {
            result = &mut completion => result,
            result = &mut ready_completion => result,
        }
    };
    assert!(
        tokio::time::timeout(Duration::from_millis(100), early_completion)
            .await
            .is_err()
    );

    peer.ceremony.persist(&root.path().join("peer.bundle"), peer.output)?;
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::try_join!(
            completion,
            ready_completion,
            peer.ceremony.confirm_completion(&mut peer.participants, peer.completion),
        )
    })
    .await??;
    for endpoint in network.endpoints {
        endpoint.close().await;
    }
    Ok(())
}

#[tokio::test]
async fn completion_fails_when_peer_cannot_persist() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let local_file = root.path().join("local.bundle");
    let peer_file = root.path().join("peer.bundle");
    fs_err::write(&peer_file, b"existing bundle")?;
    let mut network = TestCeremony::create_dealings(2, 2).await?;
    let mut validators = network.complete_dkg().await?;
    let mut local = validators.pop().unwrap();
    let mut peer = validators.pop().unwrap();
    local.ceremony.persist(&local_file, local.output)?;
    let endpoint = network
        .endpoints
        .iter()
        .find(|endpoint| endpoint.id() == peer.ceremony.endpoint_secret.public())
        .unwrap();

    let (local_result, peer_result) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            local.ceremony.confirm_completion(&mut local.participants, local.completion),
            async {
                let result = async {
                    peer.ceremony.persist(&peer_file, peer.output)?;
                    peer.ceremony.confirm_completion(&mut peer.participants, peer.completion).await
                }
                .await;
                endpoint.close().await;
                result
            },
        )
    })
    .await?;
    let error = peer_result.expect_err("the peer must not overwrite an existing bundle");
    assert!(error.to_string().contains("storage key bundle already exists"));
    let error = local_result.expect_err("missing peer completion must not report success");
    assert!(format!("{error:#}").contains("failed to read peer ceremony completion"));
    assert_eq!(fs_err::read(peer_file)?, b"existing bundle");
    assert!(local_file.exists(), "a peer failure must not delete the local bundle");
    for endpoint in network.endpoints {
        endpoint.close().await;
    }
    Ok(())
}

#[rstest::rstest]
#[case::disconnect(true)]
#[case::truncated_message(false)]
#[tokio::test]
async fn completion_rejects_interrupted_message(#[case] disconnect: bool) -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let mut network = TestCeremony::create_dealings(2, 2).await?;
    let mut validators = network.complete_dkg().await?;
    let mut local = validators.pop().unwrap();
    let mut peer = validators.pop().unwrap();
    local.ceremony.persist(&root.path().join("local.bundle"), local.output)?;
    let (connection, mut send, mut receive) =
        peer.participants.session.authenticated_peers.pop().unwrap().into_streams();
    let (result, interrupted) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            local.ceremony.confirm_completion(&mut local.participants, local.completion),
            async {
                receive.read_exact(&mut [0; Completion::BYTES]).await?;
                if disconnect {
                    connection.close(0u8.into(), b"completion interrupted");
                } else {
                    let bytes = peer.completion.encode();
                    send.write_all(&bytes[..bytes.len() - 1]).await?;
                    send.finish()?;
                }
                Ok::<_, anyhow::Error>(())
            },
        )
    })
    .await?;
    interrupted?;
    let error = result.expect_err("an incomplete completion message must not report success");
    assert!(format!("{error:#}").contains("failed to read peer ceremony completion"));
    for endpoint in network.endpoints {
        endpoint.close().await;
    }
    Ok(())
}
