use anyhow::Result;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey;
use rand_core_06::OsRng;

use super::*;

#[tokio::test]
async fn authentication_signature_commits_to_challenge() -> anyhow::Result<()> {
    let signer = ValidatorSigner::new_local(SigningKey::new());
    let challenge = Challenge::random(&mut OsRng);
    let different = Challenge::random(&mut OsRng);
    let channel_binding = [42; 32];
    let response = challenge.sign(&signer, &channel_binding).await?;

    assert!(response.verify_against(&different, &channel_binding).is_err());
    Ok(())
}

#[test]
fn authentication_signature_commits_to_domain() {
    let signing_key = SigningKey::new();
    let challenge = Challenge::random(&mut OsRng);
    let channel_binding = [42; 32];
    let mut commitment = b"different-protocol-domain".to_vec();
    commitment.extend_from_slice(&channel_binding);
    commitment.extend_from_slice(&challenge.encode());
    let response = ChallengeResponse {
        validator_public_key: signing_key.public_key(),
        signature: signing_key.sign(Hasher::hash(&commitment)),
    };

    assert!(response.verify_against(&challenge, &channel_binding).is_err());
}

#[tokio::test]
async fn authentication_rejects_changed_channel_binding() -> Result<()> {
    let signer = ValidatorSigner::new_local(SigningKey::new());
    let challenge = Challenge::decode(&[7; 32])?;
    let binding = [42; 32];
    let response = challenge.sign(&signer, &binding).await?;
    assert_eq!(response.verify_against(&challenge, &binding)?, signer.public_key());
    let response = challenge.sign(&signer, &binding).await?;
    assert!(response.verify_against(&challenge, &[43; 32]).is_err());
    Ok(())
}

/// Peers hash the V1 domain, 32 binding bytes of 42, then 32 challenge bytes of 7.
#[test]
fn authentication_challenge_eidos_vector() {
    let challenge = Challenge::decode(&[7; 32]).unwrap();
    assert_eq!(
        hex::encode(challenge.commitment(&[42; 32]).as_bytes()),
        "5a7b52d9b6f995721cb76b67b675af11e449cfd8e6bde85fedcd993eaee5ea31"
    );
}
