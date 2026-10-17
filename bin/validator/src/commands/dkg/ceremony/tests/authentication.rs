use std::net::{Ipv4Addr, UdpSocket};
use std::time::Duration;

use anyhow::Context;
use iroh::endpoint::Side;
use tokio::task::JoinSet;

use super::*;
use crate::commands::dkg::ceremony::challenge::{Challenge, ChallengeResponse};
use crate::commands::dkg::ceremony::peer::ConnectedPeer;

#[tokio::test]
async fn authentication_rejects_mitm_relayed_responses() -> TestResult {
    let mut secrets = std::array::from_fn::<_, 4, _>(|_| IrohSecretKey::generate());
    secrets.sort_by_key(IrohSecretKey::public);
    let [a_secret, b_secret, proxy_secret_a, proxy_secret_b] = secrets;
    let (a, a_lookup) = bind_test_endpoint(a_secret.clone()).await?;
    let (b, b_lookup) = bind_test_endpoint(b_secret.clone()).await?;
    let (proxy_a, _) = bind_test_endpoint(proxy_secret_a).await?;
    let (proxy_b, _) = bind_test_endpoint(proxy_secret_b).await?;
    a_lookup.add_endpoint_info(proxy_a.addr());
    b_lookup.add_endpoint_info(proxy_b.addr());

    let a_key = SigningKey::new();
    let b_key = SigningKey::new();
    let a_ceremony = test_ceremony(&a_key, a_secret, vec![(proxy_a.id(), b_key.public_key())]);
    let b_ceremony = test_ceremony(&b_key, b_secret, vec![(proxy_b.id(), a_key.public_key())]);

    // Forward challenges and responses between two attacker-owned connections.
    //
    // The proxy has neither validator's signing key. Valid signatures from one connection
    // must not authenticate the proxy on the other connection.
    let relay_challenges = async {
        let (a_connection, b_connection) = tokio::try_join!(
            async {
                Ok::<_, anyhow::Error>(proxy_a.accept().await.context("A did not dial")?.await?)
            },
            async {
                Ok::<_, anyhow::Error>(proxy_b.accept().await.context("B did not dial")?.await?)
            },
        )?;
        let ((mut a_send, mut a_recv), (mut b_send, mut b_recv)) =
            tokio::try_join!(a_connection.accept_bi(), b_connection.accept_bi())?;
        let mut a_challenge = [0; Challenge::BYTES];
        let mut b_challenge = [0; Challenge::BYTES];
        tokio::try_join!(a_recv.read_exact(&mut a_challenge), b_recv.read_exact(&mut b_challenge))?;
        tokio::try_join!(a_send.write_all(&b_challenge), b_send.write_all(&a_challenge))?;
        let mut a_response = [0; ChallengeResponse::BYTES];
        let mut b_response = [0; ChallengeResponse::BYTES];
        tokio::try_join!(a_recv.read_exact(&mut a_response), b_recv.read_exact(&mut b_response))?;
        tokio::try_join!(a_send.write_all(&b_response), b_send.write_all(&a_response))?;
        Ok::<_, anyhow::Error>((a_connection, b_connection, a_send, a_recv, b_send, b_recv))
    };

    let (a_result, b_result, proxy_connections) =
        tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(
                a_ceremony.authenticate_peers(&a),
                b_ceremony.authenticate_peers(&b),
                relay_challenges,
            )
        })
        .await?;
    let _proxy_connections = proxy_connections?;
    for result in [a_result, b_result] {
        let error = result.err().expect("MITM-relayed responses must not authenticate a peer");
        assert!(
            format!("{error:#}").contains("peer challenge response signature is invalid"),
            "{error:#}",
        );
    }

    for endpoint in [a, b, proxy_a, proxy_b] {
        endpoint.close().await;
    }
    Ok(())
}

#[rstest::rstest]
#[case::dialer(true)]
#[case::acceptor(false)]
#[tokio::test]
async fn authentication_waits_for_a_late_peer(#[case] local_is_dialer: bool) -> TestResult {
    let remote_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    let remote_address = remote_socket.local_addr()?;
    let mut secrets = [IrohSecretKey::generate(), IrohSecretKey::generate()];
    secrets.sort_by_key(IrohSecretKey::public);
    if !local_is_dialer {
        secrets.reverse();
    }
    let [local_secret, remote_secret] = secrets;
    let local_signing_key = SigningKey::new();
    let remote_signing_key = SigningKey::new();
    let mut ceremony = test_ceremony(
        &local_signing_key,
        local_secret,
        vec![(remote_secret.public(), remote_signing_key.public_key())],
    );
    ceremony.peers.insert(
        remote_secret.public(),
        (
            iroh::EndpointAddr::new(remote_secret.public()).with_ip_addr(remote_address),
            remote_signing_key.public_key(),
        ),
    );
    let endpoint = ceremony.bind_endpoint().await?;

    // Reserve the peer's UDP port until its endpoint starts.
    let authentication = ceremony.authenticate_peers(&endpoint);
    tokio::pin!(authentication);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut authentication)
            .await
            .is_err(),
        "authentication must wait while the peer is offline",
    );

    let mut remote_ceremony = test_ceremony(
        &remote_signing_key,
        remote_secret,
        vec![(endpoint.id(), local_signing_key.public_key())],
    );
    remote_ceremony.bind_address = Some(remote_address);
    remote_ceremony
        .peers
        .insert(endpoint.id(), (endpoint.addr(), local_signing_key.public_key()));
    drop(remote_socket);
    let remote = remote_ceremony.bind_endpoint().await?;
    let (local_peers, remote_peers) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::try_join!(authentication, remote_ceremony.authenticate_peers(&remote))
    })
    .await??;
    assert_eq!(local_peers.authenticated_peers.len(), 1);
    assert_eq!(remote_peers.authenticated_peers.len(), 1);
    assert_eq!(
        local_peers.authenticated_peers[0].connection().side(),
        if local_is_dialer { Side::Client } else { Side::Server },
    );
    assert_eq!(
        remote_peers.authenticated_peers[0].connection().side(),
        if local_is_dialer { Side::Server } else { Side::Client },
    );
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
        local_secret,
        vec![
            (remote.id(), SigningKey::new().public_key()),
            (missing_secret.public(), SigningKey::new().public_key()),
        ],
    );
    let untrusted_signer = ValidatorSigner::new_local(SigningKey::new());
    let (result, _remote_peer) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(ceremony.authenticate_peers(&endpoint), async {
            ConnectedPeer::connect(&remote, endpoint.id().into())
                .await?
                .authenticate(&local_signing_key.public_key(), &untrusted_signer)
                .await
        })
    })
    .await?;
    let error = result
        .err()
        .expect("authentication failure must abort without the missing peer");
    assert!(
        format!("{error:#}")
            .contains("peer validator key does not match the key configured for endpoint")
    );

    endpoint.close().await;
    remote.close().await;
    Ok(())
}

#[rstest::rstest]
#[case::duplicate_key(false)]
#[case::swapped_keys(true)]
#[tokio::test]
async fn authentication_rejects_keys_configured_for_other_endpoints(
    #[case] swapped_keys: bool,
) -> TestResult {
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
        secret,
        vec![
            (endpoint_b.id(), signing_key_b.public_key()),
            (endpoint_c.id(), signing_key_c.public_key()),
        ],
    );

    let mut authentications = JoinSet::new();
    let wrong_key_b = if swapped_keys {
        signing_key_c
    } else {
        signing_key_b.clone()
    };
    for (remote, signing_key) in
        [(endpoint_b.clone(), wrong_key_b), (endpoint_c.clone(), signing_key_b)]
    {
        let local_id = endpoint.id();
        let expected_key = signing_key_a.public_key();
        let signer = ValidatorSigner::new_local(signing_key);
        authentications.spawn(async move {
            let connection = if remote.id() < local_id {
                ConnectedPeer::connect(&remote, local_id.into()).await?
            } else {
                let incoming = remote.accept().await.expect("test endpoint must stay open");
                ConnectedPeer::accept(incoming).await?
            };
            connection.authenticate(&expected_key, &signer).await
        });
    }
    // Keep completed remote peers in the task set until local authentication stops. A rejected key
    // can abort the ceremony before the other remote peer authenticates.
    let result =
        tokio::time::timeout(Duration::from_secs(10), ceremony.authenticate_peers(&endpoint))
            .await?;
    let error = result
        .err()
        .expect("a key from another configured peer must not authenticate this endpoint");
    let error = format!("{error:#}");
    assert!(
        error.contains("peer validator key does not match the key configured for endpoint"),
        "{error}",
    );

    drop(authentications);
    endpoint.close().await;
    endpoint_b.close().await;
    endpoint_c.close().await;
    Ok(())
}
