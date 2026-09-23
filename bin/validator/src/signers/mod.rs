mod kms;
pub use kms::{KmsSigner, decrypt_key_material};
use miden_node_proto::domain::encryption::{
    TransactionEncryptionKeyInfo,
    TransactionEncryptionScheme,
};
use miden_node_tracing::spawn::spawn_blocking_in_current_span;
use miden_protocol::Word;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::{PublicKey, Signature, SigningKey};
use miden_protocol::crypto::dsa::eddsa_25519_sha512::{
    KeyExchangeKey,
    PublicKey as EncryptionPublicKey,
};
#[cfg(test)]
use miden_protocol::crypto::ies::SealingKey;
use miden_protocol::crypto::ies::{SealedMessage, UnsealingKey};
use miden_protocol::utils::serde::{Deserializable, Serializable};

// VALIDATOR SIGNER
// =================================================================================================

/// Signer that the Validator uses to sign blocks.
pub enum ValidatorSigner {
    Kms(KmsSigner),
    Local(SigningKey),
}

impl ValidatorSigner {
    /// Constructs a signer which uses an AWS KMS key for signing.
    ///
    /// See [`KmsSigner`] for details as to env var configuration and AWS IAM policies
    /// required to use this functionality.
    pub async fn new_kms(key_id: impl Into<String>) -> anyhow::Result<Self> {
        let kms_signer = KmsSigner::new(key_id).await?;
        Ok(Self::Kms(kms_signer))
    }

    /// Constructs a signer which uses a local secret key for signing.
    pub fn new_local(secret_key: SigningKey) -> Self {
        Self::Local(secret_key)
    }

    /// Returns the public key corresponding to the configured signer.
    pub fn public_key(&self) -> PublicKey {
        match self {
            Self::Kms(signer) => signer.public_key(),
            Self::Local(signer) => signer.public_key(),
        }
    }

    /// Signs a commitment using the configured signer.
    pub async fn sign_commitment(&self, commitment: Word) -> anyhow::Result<Signature> {
        let signature = match self {
            Self::Kms(signer) => signer.sign(commitment).await?,
            Self::Local(signer) => spawn_blocking_in_current_span({
                let signer = signer.clone();
                move || signer.sign(commitment)
            })
            .await
            .unwrap_or_else(|e| std::panic::resume_unwind(e.into_panic())),
        };

        Ok(signature)
    }
}

// TRANSACTION INPUT DECRYPTER
// =================================================================================================

/// Decryption counterpart to [`ValidatorSigner`] for the shared transaction encryption
/// (submission) key.
///
/// Unlike the signing key, the key material behind an implementation must be identical across
/// every validator in the set. This lets any validator unseal an encrypted submission, regardless
/// of which validator attested the encryption key to the client.
///
/// The interface deliberately does not assume that secret key bytes exist in the validator
/// process: an implementation may hold a local secret (see
/// [`LocalX25519TransactionInputDecrypter`]) or delegate decryption to an external system such as
/// a TEE that only exposes a decrypt operation.
#[tonic::async_trait]
pub trait TransactionInputDecrypter: Send + Sync {
    /// Returns the public metadata of the current encryption key.
    async fn encryption_key(&self) -> anyhow::Result<TransactionEncryptionKeyInfo>;

    /// Decrypts transaction inputs sealed against the current encryption key.
    ///
    /// The ciphertext is a serialized [`SealedMessage`].
    async fn decrypt_transaction_inputs(
        &self,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> anyhow::Result<Vec<u8>>;
}

/// [`TransactionInputDecrypter`] backed by a locally provisioned X25519 shared secret.
pub struct LocalX25519TransactionInputDecrypter {
    secret_key: KeyExchangeKey,
}

impl LocalX25519TransactionInputDecrypter {
    /// The IES scheme used for transaction input encryption.
    pub const SCHEME: TransactionEncryptionScheme =
        TransactionEncryptionScheme::X25519XChaCha20Poly1305;

    /// Constructs a decrypter from a locally provisioned shared secret.
    pub fn new(secret_key: KeyExchangeKey) -> Self {
        Self { secret_key }
    }

    /// Returns the public key of the shared encryption key.
    pub fn public_key(&self) -> EncryptionPublicKey {
        self.secret_key.public_key()
    }

    /// Returns the opaque identifier of the current encryption key: the first 4 bytes of the public
    /// key commitment.
    pub fn key_id(&self) -> Vec<u8> {
        self.public_key().to_commitment().to_bytes()[..4].to_vec()
    }

    /// Returns the sealing key that clients use to encrypt messages to the validator set.
    #[cfg(test)]
    pub fn sealing_key(&self) -> SealingKey {
        SealingKey::X25519XChaCha20Poly1305(self.public_key())
    }
}

#[tonic::async_trait]
impl TransactionInputDecrypter for LocalX25519TransactionInputDecrypter {
    async fn encryption_key(&self) -> anyhow::Result<TransactionEncryptionKeyInfo> {
        Ok(TransactionEncryptionKeyInfo {
            scheme: Self::SCHEME,
            key_id: self.key_id(),
            public_key: self.public_key().to_bytes(),
            next_key: None,
        })
    }

    async fn decrypt_transaction_inputs(
        &self,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        use anyhow::Context;

        let message = SealedMessage::read_from_bytes(ciphertext)
            .context("failed to deserialize the sealed message")?;

        let secret_key = self.secret_key.clone();
        let associated_data = associated_data.to_vec();
        spawn_blocking_in_current_span(move || {
            UnsealingKey::X25519XChaCha20Poly1305(secret_key)
                .unseal_bytes_with_associated_data(message, &associated_data)
                .context("AEAD authentication failed")
        })
        .await
        .unwrap_or_else(|e| std::panic::resume_unwind(e.into_panic()))
    }
}

// TESTS
// =================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::utils::serde::Deserializable;
    use rand::rng;

    use super::*;

    fn decrypter_from(secret: &[u8; 32]) -> LocalX25519TransactionInputDecrypter {
        LocalX25519TransactionInputDecrypter::new(KeyExchangeKey::read_from_bytes(secret).unwrap())
    }

    /// Loading the same shared secret must yield the same key metadata and attestation commitment
    /// on every validator instance.
    #[tokio::test]
    async fn same_secret_yields_same_public_material() {
        let genesis = Word::try_from([1u64, 2, 3, 4]).unwrap();
        let info_a = decrypter_from(&[7u8; 32]).encryption_key().await.unwrap();
        let info_b = decrypter_from(&[7u8; 32]).encryption_key().await.unwrap();

        assert_eq!(info_a, info_b);
        assert_eq!(info_a.attestation_commitment(genesis), info_b.attestation_commitment(genesis));
    }

    /// Different secrets must yield different public keys and key ids.
    #[tokio::test]
    async fn different_secrets_yield_different_public_material() {
        let genesis = Word::try_from([1u64, 2, 3, 4]).unwrap();
        let info_a = decrypter_from(&[7u8; 32]).encryption_key().await.unwrap();
        let info_b = decrypter_from(&[8u8; 32]).encryption_key().await.unwrap();

        assert_eq!(info_a.scheme, info_b.scheme);
        assert_ne!(info_a.public_key, info_b.public_key);
        assert_ne!(info_a.key_id, info_b.key_id);
        assert_ne!(info_a.attestation_commitment(genesis), info_b.attestation_commitment(genesis));
    }

    /// A message sealed against the decrypter's sealing key must decrypt to the original plaintext,
    /// and decryption must reject a mismatched associated data or a mismatched key.
    #[tokio::test]
    async fn seal_decrypt_roundtrip() {
        let mut rng = rng();
        let decrypter = decrypter_from(&[7u8; 32]);
        let plaintext = b"transaction inputs";
        let associated_data = b"scheme|key_id|chain|tx";

        let sealed = decrypter
            .sealing_key()
            .seal_bytes_with_associated_data(&mut rng, plaintext, associated_data)
            .unwrap()
            .to_bytes();
        let opened = decrypter.decrypt_transaction_inputs(&sealed, associated_data).await.unwrap();
        assert_eq!(opened.as_slice(), plaintext);

        // Mismatched associated data must fail authentication.
        assert!(
            decrypter
                .decrypt_transaction_inputs(&sealed, b"wrong associated data")
                .await
                .is_err()
        );

        // A different shared secret must fail to decrypt.
        let other = decrypter_from(&[8u8; 32]);
        assert!(other.decrypt_transaction_inputs(&sealed, associated_data).await.is_err());

        // Garbage ciphertext must fail to deserialize.
        assert!(
            decrypter
                .decrypt_transaction_inputs(b"not a sealed message", associated_data)
                .await
                .is_err()
        );
    }
}
