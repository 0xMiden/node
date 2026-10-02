use std::time::Duration;

use iroh::endpoint::{AfterHandshakeOutcome, Connection, EndpointHooks};
use tokio::sync::mpsc;

use super::*;
use crate::commands::dkg_p2p::ceremony::peer::ConnectedPeer;

#[rstest::rstest]
#[case::failed_connection(b"unsupported-protocol")]
#[case::unconfigured_endpoint(Ceremony::ALPN)]
#[tokio::test]
async fn unrelated_connection_does_not_abort_authentication(#[case] alpn: &[u8]) -> TestResult {
    let mut secrets = [IrohSecretKey::generate(), IrohSecretKey::generate()];
    secrets.sort_by_key(IrohSecretKey::public);
    let [peer_secret, local_secret] = secrets;
    let (endpoint, _) = bind_test_endpoint(local_secret.clone()).await?;
    let (peer, peer_lookup) = bind_test_endpoint(peer_secret).await?;
    peer_lookup.add_endpoint_info(endpoint.addr());
    let (unrelated, _) = bind_test_endpoint(IrohSecretKey::generate()).await?;
    let local_signing_key = SigningKey::new();
    let peer_signing_key = SigningKey::new();
    let ceremony = test_ceremony(
        &local_signing_key,
        vec![local_signing_key.public_key(), peer_signing_key.public_key()],
        local_secret,
        BTreeSet::from([peer.id()]),
    );
    let signer = ValidatorSigner::new_local(peer_signing_key);

    let (peers, _remote_peer) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::try_join!(ceremony.authenticate_peers(&endpoint), async {
            let connection = unrelated.connect(endpoint.addr(), alpn).await;
            if alpn == Ceremony::ALPN {
                if let Ok(connection) = connection {
                    connection.closed().await;
                }
            } else {
                assert!(connection.is_err(), "the unsupported protocol must fail establishment");
            }

            ConnectedPeer::connect(&peer, endpoint.id())
                .await?
                .authenticate(&ceremony.validator_set, &signer)
                .await
        })
    })
    .await??;
    assert_eq!(peers.authenticated_peers.len(), 1);
    assert_eq!(peers.authenticated_peers[0].validator_public_key(), &signer.public_key());

    endpoint.close().await;
    peer.close().await;
    unrelated.close().await;
    Ok(())
}

/// Holds incoming establishment open for one endpoint through Iroh's connection hook.
///
/// The notification lets tests wait for occupied capacity without relying on a sleep.
#[derive(Debug)]
struct StallConnection {
    endpoint: EndpointId,
    started: mpsc::UnboundedSender<()>,
}

impl EndpointHooks for StallConnection {
    async fn after_handshake(&self, connection: &Connection) -> AfterHandshakeOutcome {
        if connection.remote_id() == self.endpoint {
            self.started.send(()).expect("test must keep the notification receiver open");
            std::future::pending().await
        } else {
            AfterHandshakeOutcome::Accept
        }
    }
}

#[rstest::rstest]
#[case::one_stalled_connection(1)]
#[case::full_capacity(Ceremony::MAX_PENDING_CONNECTIONS)]
#[tokio::test]
async fn stalled_connections_do_not_prevent_peer_authentication(
    #[case] stalled_count: usize,
) -> TestResult {
    let mut secrets = [IrohSecretKey::generate(), IrohSecretKey::generate()];
    secrets.sort_by_key(IrohSecretKey::public);
    let [peer_secret, local_secret] = secrets;
    let (peer, peer_lookup) = bind_test_endpoint(peer_secret).await?;
    let (unrelated, _) = bind_test_endpoint(IrohSecretKey::generate()).await?;
    let (started, mut stalled) = mpsc::unbounded_channel();
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(local_secret.clone())
        .alpns(vec![Ceremony::ALPN.to_vec()])
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0")?
        .hooks(StallConnection { endpoint: unrelated.id(), started })
        .bind()
        .await?;
    peer_lookup.add_endpoint_info(endpoint.addr());
    let local_signing_key = SigningKey::new();
    let peer_signing_key = SigningKey::new();
    let ceremony = test_ceremony(
        &local_signing_key,
        vec![local_signing_key.public_key(), peer_signing_key.public_key()],
        local_secret,
        BTreeSet::from([peer.id()]),
    );
    let signer = ValidatorSigner::new_local(peer_signing_key);

    let (peers, _remote_peer) = tokio::time::timeout(Duration::from_secs(20), async {
        tokio::try_join!(ceremony.authenticate_peers(&endpoint), async {
            let mut connections = Vec::new();
            for _ in 0..stalled_count {
                connections.push(unrelated.connect(endpoint.addr(), Ceremony::ALPN).await?);
                stalled.recv().await.expect("connection must reach the establishment hook");
            }
            if stalled_count == Ceremony::MAX_PENDING_CONNECTIONS {
                let result = unrelated.connect(endpoint.addr(), Ceremony::ALPN).await;
                assert!(result.is_err(), "excess connections must be refused");

                // Wait for the establishment timeouts to release all occupied capacity.
                for connection in &connections {
                    connection.closed().await;
                }
            }

            let authenticated = tokio::time::timeout(Duration::from_secs(5), async {
                ConnectedPeer::connect(&peer, endpoint.id())
                    .await?
                    .authenticate(&ceremony.validator_set, &signer)
                    .await
            })
            .await??;
            Ok::<_, anyhow::Error>(authenticated)
        })
    })
    .await??;
    assert_eq!(peers.authenticated_peers.len(), 1);
    assert_eq!(peers.authenticated_peers[0].validator_public_key(), &signer.public_key());

    endpoint.close().await;
    peer.close().await;
    unrelated.close().await;
    Ok(())
}

#[rstest::rstest]
#[case::duplicate_incoming(true)]
#[case::wrong_direction(false)]
#[tokio::test]
async fn extra_connection_does_not_replace_an_authenticated_peer(
    #[case] remote_is_dialer: bool,
) -> TestResult {
    let mut secrets =
        [IrohSecretKey::generate(), IrohSecretKey::generate(), IrohSecretKey::generate()];
    secrets.sort_by_key(IrohSecretKey::public);
    let [missing_secret, lower_secret, higher_secret] = secrets;
    let (local_secret, peer_secret) = if remote_is_dialer {
        (higher_secret, lower_secret)
    } else {
        (lower_secret, higher_secret)
    };
    let (endpoint, lookup) = bind_test_endpoint(local_secret.clone()).await?;
    let (peer, peer_lookup) = bind_test_endpoint(peer_secret).await?;
    let (missing, missing_lookup) = bind_test_endpoint(missing_secret).await?;
    lookup.add_endpoint_info(peer.addr());
    peer_lookup.add_endpoint_info(endpoint.addr());
    missing_lookup.add_endpoint_info(endpoint.addr());
    let local_signing_key = SigningKey::new();
    let peer_signing_key = SigningKey::new();
    let missing_signing_key = SigningKey::new();
    let ceremony = test_ceremony(
        &local_signing_key,
        vec![
            local_signing_key.public_key(),
            peer_signing_key.public_key(),
            missing_signing_key.public_key(),
        ],
        local_secret,
        BTreeSet::from([peer.id(), missing.id()]),
    );
    let peer_signer = ValidatorSigner::new_local(peer_signing_key);
    let missing_signer = ValidatorSigner::new_local(missing_signing_key);

    let (peers, remote_peers) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::try_join!(ceremony.authenticate_peers(&endpoint), async {
            let connection = if remote_is_dialer {
                ConnectedPeer::connect(&peer, endpoint.id()).await?
            } else {
                let incoming = peer.accept().await.expect("test endpoint must stay open");
                ConnectedPeer::accept(incoming).await?
            };
            let authenticated =
                connection.authenticate(&ceremony.validator_set, &peer_signer).await?;

            // Dial again while the ceremony still waits for the last peer.
            //
            // The extra connection must close without replacing the authenticated connection.
            if let Ok(extra) = peer.connect(endpoint.addr(), Ceremony::ALPN).await {
                extra.closed().await;
            }
            let last = ConnectedPeer::connect(&missing, endpoint.id())
                .await?
                .authenticate(&ceremony.validator_set, &missing_signer)
                .await?;
            Ok::<_, anyhow::Error>([authenticated, last])
        })
    })
    .await??;
    assert_eq!(peers.authenticated_peers.len(), 2);
    assert!(remote_peers[0].connection().close_reason().is_none());

    endpoint.close().await;
    peer.close().await;
    missing.close().await;
    Ok(())
}
