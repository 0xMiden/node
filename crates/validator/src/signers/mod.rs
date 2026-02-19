mod kms;
pub use kms::KmsSigner;
use miden_node_utils::signer::BlockSigner;
use miden_protocol::block::BlockHeader;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::{SecretKey, Signature};

// VALIDATOR SIGNER
// =================================================================================================

/// Signer that the Validator uses to sign blocks.
pub enum ValidatorSigner {
    Kms(KmsSigner),
    Local(SecretKey),
}

impl ValidatorSigner {
    /// Constructs a signer which uses an AWS KMS key for signing.
    pub async fn new_kms(key_id: impl Into<String>) -> anyhow::Result<Self> {
        let kms_signer = KmsSigner::new(key_id).await?;
        Ok(Self::Kms(kms_signer))
    }

    /// Constructs a signer which uses a local secret key for signing.
    pub fn new_local(secret_key: SecretKey) -> Self {
        Self::Local(secret_key)
    }

    /// Signs a block header using the configured signer.
    pub async fn sign(&self, header: &BlockHeader) -> anyhow::Result<Signature> {
        match self {
            Self::Kms(signer) => {
                let sig = signer.sign(header).await?;
                Ok(sig)
            },
            Self::Local(signer) => {
                let sig = <SecretKey as BlockSigner>::sign(signer, header).await?;
                Ok(sig)
            },
        }
    }
}
