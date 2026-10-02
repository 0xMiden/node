use std::time::Duration;

use tokio::task::JoinSet;

use super::*;
use crate::commands::dkg_p2p::ceremony::peer::ConnectedPeer;

#[rstest::rstest]
#[case::dialer(true)]
#[case::acceptor(false)]
#[tokio::test]
async fn authentication_waits_for_a_late_peer(#[case] local_is_dialer: bool) -> TestResult {
    let mut secrets = [IrohSecretKey::generate(), IrohSecretKey::generate()];
    secrets.sort_by_key(IrohSecretKey::public);
    if !local_is_dialer {
        secrets.reverse();
    }
    let [local_secret, remote_secret] = secrets;
    let (endpoint, lookup) = bind_test_endpoint(local_secret.clone()).await?;
    let local_signing_key = SigningKey::new();
    let remote_signing_key = SigningKey::new();
    let validator_keys = vec![local_signing_key.public_key(), remote_signing_key.public_key()];
    let ceremony = test_ceremony(
        &local_signing_key,
        validator_keys.clone(),
        local_secret,
        BTreeSet::from([remote_secret.public()]),
    );

    // Start without the peer or its address lookup entry.
    //
    // A dial attempt cannot resolve an address until the peer starts.
    let authentication = ceremony.authenticate_peers(&endpoint);
    tokio::pin!(authentication);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut authentication)
            .await
            .is_err(),
        "authentication must wait while the peer is offline",
    );

    let (remote, remote_lookup) = bind_test_endpoint(remote_secret.clone()).await?;
    lookup.add_endpoint_info(remote.addr());
    remote_lookup.add_endpoint_info(endpoint.addr());
    let remote_ceremony = test_ceremony(
        &remote_signing_key,
        validator_keys,
        remote_secret,
        BTreeSet::from([endpoint.id()]),
    );
    let (local_peers, remote_peers) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::try_join!(authentication, remote_ceremony.authenticate_peers(&remote))
    })
    .await??;
    assert_eq!(local_peers.authenticated_peers.len(), 1);
    assert_eq!(remote_peers.authenticated_peers.len(), 1);
    assert_eq!(
        local_peers.authenticated_peers[0].validator_public_key(),
        &remote_signing_key.public_key(),
    );
    assert_eq!(
        remote_peers.authenticated_peers[0].validator_public_key(),
        &local_signing_key.public_key(),
    );

    endpoint.close().await;
    remote.close().await;
    Ok(())
}

#[tokio::test]
async fn authentication_failure_aborts_while_another_peer_is_offline() -> TestResult {
    let mut secrets =
        [IrohSecretKey::generate(), IrohSecretKey::generate(), IrohSecretKey::generate()];
    secrets.sort_by_key(IrohSecretKey::public);
    let [missing_secret, remote_secret, local_secret] = secrets;
    let (endpoint, lookup) = bind_test_endpoint(local_secret.clone()).await?;
    let (remote, remote_lookup) = bind_test_endpoint(remote_secret).await?;
    lookup.add_endpoint_info(remote.addr());
    remote_lookup.add_endpoint_info(endpoint.addr());
    let local_signing_key = SigningKey::new();
    let ceremony = test_ceremony(
        &local_signing_key,
        vec![
            local_signing_key.public_key(),
            SigningKey::new().public_key(),
            SigningKey::new().public_key(),
        ],
        local_secret,
        BTreeSet::from([remote.id(), missing_secret.public()]),
    );
    let untrusted_signer = ValidatorSigner::new_local(SigningKey::new());
    let (result, _remote_peer) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(ceremony.authenticate_peers(&endpoint), async {
            ConnectedPeer::connect(&remote, endpoint.id())
                .await?
                .authenticate(&ceremony.validator_set, &untrusted_signer)
                .await
        })
    })
    .await?;
    let error = result
        .err()
        .expect("authentication failure must abort without the missing peer");
    assert!(format!("{error:#}").contains("peer validator key is not committed by genesis"));

    endpoint.close().await;
    remote.close().await;
    Ok(())
}

#[tokio::test]
async fn authentication_rejects_two_endpoints_using_the_same_validator_key() -> TestResult {
    let secret = IrohSecretKey::generate();
    let (endpoint, lookup) = bind_test_endpoint(secret.clone()).await?;
    let (endpoint_b, lookup_b) = bind_test_endpoint(IrohSecretKey::generate()).await?;
    let (endpoint_c, lookup_c) = bind_test_endpoint(IrohSecretKey::generate()).await?;
    lookup.add_endpoint_info(endpoint_b.addr());
    lookup.add_endpoint_info(endpoint_c.addr());
    lookup_b.add_endpoint_info(endpoint.addr());
    lookup_c.add_endpoint_info(endpoint.addr());

    let signing_key_a = SigningKey::new();
    let signing_key_b = SigningKey::new();
    let signing_key_c = SigningKey::new();
    let ceremony = test_ceremony(
        &signing_key_a,
        vec![
            signing_key_a.public_key(),
            signing_key_b.public_key(),
            signing_key_c.public_key(),
        ],
        secret,
        BTreeSet::from([endpoint_b.id(), endpoint_c.id()]),
    );

    let mut authentications = JoinSet::new();
    for remote in [endpoint_b.clone(), endpoint_c.clone()] {
        let local_id = endpoint.id();
        let validator_set = Arc::clone(&ceremony.validator_set);
        // Authenticate both remote endpoints with B's key.
        //
        // Each endpoint can prove key ownership, but the pair cannot represent both B and C.
        let signer = ValidatorSigner::new_local(signing_key_b.clone());
        authentications.spawn(async move {
            let connection = if remote.id() < local_id {
                ConnectedPeer::connect(&remote, local_id).await?
            } else {
                let incoming = remote.accept().await.expect("test endpoint must stay open");
                ConnectedPeer::accept(incoming).await?
            };
            connection.authenticate(&validator_set, &signer).await
        });
    }
    let (result, remote_peers) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(ceremony.authenticate_peers(&endpoint), async {
            let mut peers = Vec::new();
            while let Some(result) = authentications.join_next().await {
                // Retain peer results without requiring authentication to succeed.
                //
                // The validator can reject duplicate identities before a peer reads its response.
                peers.push(result?);
            }
            // Return the peers to keep their connections alive.
            //
            // The ceremony must check the complete validator set before the test drops the peers.
            Ok::<_, anyhow::Error>(peers)
        })
    })
    .await?;
    let _remote_peers = remote_peers?;
    let error = result.err().expect("duplicate validator identities must stop authentication");
    let error = format!("{error:#}");
    assert!(
        error.contains("authenticated validator keys do not form a valid validator set"),
        "{error}",
    );

    endpoint.close().await;
    endpoint_b.close().await;
    endpoint_c.close().await;
    Ok(())
}
