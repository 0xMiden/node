use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey;

use super::*;

#[tokio::test]
/// Guards the final agreement step against copying one validator's signature into another slot.
async fn final_confirmation_cannot_be_copied_between_validator_slots() -> anyhow::Result<()> {
    let first = ValidatorSigner::new_local(SigningKey::new());
    let second = ValidatorSigner::new_local(SigningKey::new());
    let genesis_commitment = Word::default();
    let digest = [7; 32];
    let confirmation = sign_final_confirmation(&first, genesis_commitment, digest).await?;

    validate_final_confirmation(
        &confirmation,
        &hex::encode(first.public_key().to_bytes()),
        genesis_commitment,
        digest,
    )?;
    let error = validate_final_confirmation(
        &confirmation,
        &hex::encode(second.public_key().to_bytes()),
        genesis_commitment,
        digest,
    )
    .unwrap_err();
    assert!(error.to_string().contains("another validator"));
    Ok(())
}
