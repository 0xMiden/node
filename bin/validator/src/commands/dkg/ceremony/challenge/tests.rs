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
        signature: signing_key.sign(Rpo256::hash(&commitment)),
    };

    assert!(response.verify_against(&challenge, &channel_binding).is_err());
}
