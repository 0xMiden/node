use anyhow::Context;
use aws_sdk_kms::error::SdkError;
use aws_sdk_kms::operation::sign::SignError;
use aws_sdk_kms::types::SigningAlgorithmSpec;
use k256::PublicKey as K256PublicKey;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::pkcs8::DecodePublicKey as _;
use miden_node_utils::signer::BlockSigner;
use miden_protocol::block::BlockHeader;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::{PublicKey, Signature};
use miden_protocol::crypto::hash::keccak::Keccak256;
use miden_tx::utils::{Deserializable, DeserializationError, Serializable};

// KMS SIGNER ERROR
// ================================================================================================

#[derive(Debug, thiserror::Error)]
pub enum KmsSignerError {
    /// The KMS backend errored out.
    #[error("KMS service failure")]
    KmsServiceError(#[source] Box<SdkError<SignError>>),
    /// The KMS backend did not error but returned an empty signature.
    #[error("KMS request returned an empty result")]
    EmptyBlob,
    /// The KMS backend returned a signature with an invalid format.
    #[error("k256 signature error")]
    K256Error(#[source] k256::ecdsa::Error),
    /// The KMS backend returned a signature with an invalid format.
    #[error("invalid signature format")]
    SignatureFormatError(#[source] DeserializationError),
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
    /// Constructs a new KMS signer and retrieves the corresponding public key from the AWS backend.
    ///
    /// The supplied `key_id` must be a valid AWS KMS key ID in the AWS region corresponding to the
    /// typical `AWS_REGION` env var.
    ///
    /// A policy statement such as the following is required to allow a process on an EC2 instance
    /// to use this signer:
    /// ```json
    /// {
    ///   "Sid": "AllowEc2RoleUseOfKey",
    ///   "Effect": "Allow",
    ///   "Principal": {
    ///     "AWS": "arn:aws:iam::<account_id>:role/<role_name>"
    ///   },
    ///   "Action": [
    ///     "kms:Sign",
    ///     "kms:Verify",
    ///     "kms:DescribeKey"
    ///     "kms:GetPublicKey"
    ///   ],
    ///   "Resource": "*"
    /// },
    /// ```
    pub async fn new(key_id: impl Into<String>) -> anyhow::Result<Self> {
        let version = aws_config::BehaviorVersion::v2026_01_12();
        let config = aws_config::load_defaults(version).await;
        let client = aws_sdk_kms::Client::new(&config);
        let key_id = key_id.into();

        // Retrieve DER-encoded SPKI.
        let pub_key_output = client.get_public_key().key_id(key_id.clone()).send().await?;
        let spki_der = pub_key_output.public_key().ok_or(KmsSignerError::EmptyBlob)?.as_ref();

        // Decode the DER-encoded SPKI and compress it.
        let kpub = K256PublicKey::from_public_key_der(spki_der)
            .context("failed to parse SPKI as secp256k1")?;
        let compressed = kpub.to_encoded_point(true); // 33 bytes, 0x02/0x03 || X.
        let sec1_compressed = compressed.as_bytes();

        // Decode the compressed SPKI as a Miden public key.
        let pub_key = PublicKey::read_from_bytes(sec1_compressed)?;
        Ok(Self { key_id, pub_key, client })
    }
}

#[async_trait::async_trait]
impl BlockSigner for KmsSigner {
    type Error = KmsSignerError;

    async fn sign(&self, header: &BlockHeader) -> Result<Signature, Self::Error> {
        // The Validator produces Ethereum-style ECDSA (secp256k1) signatures over Keccak-256
        // digests. AWS KMS does not support SHA-3 hashing for ECDSA keys
        // (ECC_SECG_P256K1 being the corresponding AWS key-spec), so we pre-hash the
        // message and pass MessageType::Digest. KMS signs the provided 32-byte digest
        // verbatim.
        let msg = header.commitment().to_bytes();
        let digest = Keccak256::hash(&msg);

        // Request signature from KMS backend.
        let sign_output = self
            .client
            .sign()
            .key_id(&self.key_id)
            .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
            .message_type(aws_sdk_kms::types::MessageType::Digest)
            .message(digest.to_bytes().into())
            .send()
            .await
            .map_err(Box::from)
            .map_err(KmsSignerError::KmsServiceError)?;

        // Decode DER-encoded signature.
        let sig_der = sign_output.signature().ok_or(KmsSignerError::EmptyBlob)?;
        // Recovery id is not used by verify(pk), so 0 is fine.
        let recovery_id = 0;
        Signature::from_der(sig_der.as_ref(), recovery_id)
            .map_err(KmsSignerError::SignatureFormatError)
    }

    fn public_key(&self) -> PublicKey {
        self.pub_key.clone()
    }
}
