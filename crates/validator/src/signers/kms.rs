use aws_sdk_kms::error::SdkError;
use aws_sdk_kms::operation::sign::SignError;
use aws_sdk_kms::types::SigningAlgorithmSpec;
use miden_node_utils::signer::BlockSigner;
use miden_protocol::block::BlockHeader;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::{PublicKey, Signature};
use miden_tx::utils::{Deserializable, DeserializationError, Serializable};

// KMS SIGNER ERROR
// ================================================================================================

#[derive(Debug, thiserror::Error)]
pub enum KmsSignerError {
    /// The KMS backend errored out.
    #[error("KMS service failure")]
    KmsServiceError(#[from] Box<SdkError<SignError>>),
    /// The KMS backend did not error but returned an empty signature.
    #[error("signing request returned empty signature")]
    EmptySignature,
    /// The KMS backend returned a signature with an invalid format.
    #[error("signature invalid format")]
    SignatureFormatError(#[from] DeserializationError),
}

// KMS SIGNER
// ================================================================================================

/// Block signer that uses AWS KMS to create signatures.
pub struct KmsSigner {
    key_id: String,
    pub_key: PublicKey,
    client: aws_sdk_kms::Client,
}

impl KmsSigner {
    pub async fn new(key_id: impl Into<String>) -> anyhow::Result<Self> {
        let version = aws_config::BehaviorVersion::v2026_01_12();
        let config = aws_config::load_defaults(version).await;
        let client = aws_sdk_kms::Client::new(&config);
        let key_id = key_id.into();

        // Retrieve public key.
        let pub_key_output = client.get_public_key().key_id(key_id.clone()).send().await?;
        if let Some(pub_key) = pub_key_output.public_key() {
            let pub_key = PublicKey::read_from_bytes(&pub_key.clone().into_inner())?;
            Ok(Self { key_id, pub_key, client })
        } else {
            anyhow::bail!("failed to retrieve public key");
        }
    }
}

#[async_trait::async_trait]
impl BlockSigner for KmsSigner {
    type Error = KmsSignerError;

    async fn sign(&self, header: &BlockHeader) -> Result<Signature, Self::Error> {
        // Request signature from KMS backend.
        let sign_output = self
            .client
            .sign()
            .key_id(&self.key_id)
            .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
            .message(header.commitment().to_bytes().into())
            .send()
            .await
            .map_err(Box::from)?;

        // Handle the returned signature.
        let sig = sign_output.signature().ok_or(KmsSignerError::EmptySignature)?;
        let sig = sig.clone().into_inner(); // todo no clone?
        Ok(Signature::read_from_bytes(&sig)?)
    }

    fn public_key(&self) -> PublicKey {
        self.pub_key.clone()
    }
}
