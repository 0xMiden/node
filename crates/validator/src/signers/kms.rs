use aws_sdk_kms::error::SdkError;
use aws_sdk_kms::operation::sign::SignError;
use aws_sdk_kms::types::SigningAlgorithmSpec;
use k256::elliptic_curve::sec1::ToEncodedPoint;
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
    KmsServiceError(#[from] Box<SdkError<SignError>>),
    /// The KMS backend did not error but returned an empty signature.
    #[error("KMS request returned an empty result")]
    EmptyBlob,
    /// The KMS backend returned a signature with an invalid format.
    #[error("invalid signature format")]
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

        // Retrieve DER-encoded SPKI (NOT a certificate).
        let pub_key_output = client.get_public_key().key_id(key_id.clone()).send().await?;
        let spki_der = pub_key_output.public_key().ok_or(KmsSignerError::EmptyBlob)?.as_ref();

        // Print OIDs for sanity (you already did this)
        let spki = spki::SubjectPublicKeyInfoRef::try_from(spki_der)?;
        println!("SPKI algorithm OID: {}", spki.algorithm.oid);
        if let Some(params) = spki.algorithm.parameters {
            println!("SPKI params: {:?}", params);
        }

        // Use k256 to decode SPKI and re-encode in the shapes Miden may expect
        use k256::pkcs8::DecodePublicKey as _;
        use k256::{EncodedPoint, PublicKey as K256PublicKey};

        let kpub = K256PublicKey::from_public_key_der(spki_der)
            .map_err(|e| anyhow::anyhow!("failed to parse SPKI as secp256k1: {e}"))?;
        let uncompressed = kpub.to_encoded_point(false); // 65 bytes, 0x04 || X || Y
        let compressed = kpub.to_encoded_point(true); // 33 bytes, 0x02/0x03 || X

        let sec1_uncompressed = uncompressed.as_bytes();
        let sec1_compressed = compressed.as_bytes();
        let raw_xy = &sec1_uncompressed[1..]; // 64 bytes X||Y

        println!(
            "encodings: compressed_len={}, uncompressed_len={}, raw_xy_len={}",
            sec1_compressed.len(),
            sec1_uncompressed.len(),
            raw_xy.len()
        );

        // Try encodings in sensible order: compressed -> uncompressed -> raw XY
        let pub_key = PublicKey::read_from_bytes(sec1_compressed)
            .or_else(|_| PublicKey::read_from_bytes(sec1_uncompressed))
            .or_else(|_| PublicKey::read_from_bytes(raw_xy))?;

        Ok(Self { key_id, pub_key, client })
    }
}

#[async_trait::async_trait]
impl BlockSigner for KmsSigner {
    type Error = KmsSignerError;

    async fn sign(&self, header: &BlockHeader) -> Result<Signature, Self::Error> {
        // 1) Compute Keccak-256 over the same bytes Miden signs
        let msg = header.commitment().to_bytes();
        let digest = Keccak256::hash(&msg); // 32 bytes
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
            .map_err(Box::from)?;

        // 3) Convert DER -> 64-byte r||s, and normalize s to low-S
        use k256::ecdsa::Signature as K256Signature;
        let sig_der = sign_output.signature().ok_or(KmsSignerError::EmptyBlob)?;
        let ksig = K256Signature::from_der(sig_der.as_ref()).map_err(|e| {
            KmsSignerError::SignatureFormatError(DeserializationError::InvalidValue(
                format!("DER decode error: {e}").into(),
            ))
        })?;
        let rs = if let Some(norm) = ksig.normalize_s() {
            norm.to_bytes()
        } else {
            ksig.to_bytes()
        }; // 64 bytes

        // 3.5) Append a recovery byte `v` to make 65 bytes (r||s||v).
        let mut sig65 = [0u8; 65];
        sig65[..64].copy_from_slice(&rs);
        sig65[64] = 0; // recovery id; not used by verify(pk), so 0 is fine

        // 4) Parse into Miden signature
        Ok(Signature::read_from_bytes(&sig65)?)
    }

    fn public_key(&self) -> PublicKey {
        self.pub_key.clone()
    }
}
