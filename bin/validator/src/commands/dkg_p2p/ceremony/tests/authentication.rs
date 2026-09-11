use std::time::Duration;

use tokio::task::JoinSet;

use super::*;
use crate::commands::dkg_p2p::ceremony::peer::ConnectedPeer;

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
        // Both endpoints can prove ownership of B's key, but neither supplies C's identity.
        let signer = ValidatorSigner::new_local(signing_key_b.clone());
        authentications.spawn(async move {
            let connection = if remote.id() < local_id {
                ConnectedPeer::connect(&remote, local_id).await?
            } else {
                ConnectedPeer::accept(&remote).await?
            };
            connection.authenticate(&validator_set, &signer).await
        });
    }
    let (result, remote_peers) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(ceremony.authenticate_peers(&endpoint), async {
            let mut peers = Vec::new();
            while let Some(result) = authentications.join_next().await {
                // Rejection may disconnect a peer before it reads the validator's response.
                peers.push(result?);
            }
            // Retain the connections while the ceremony checks the complete validator set.
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
