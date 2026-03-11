use aws_sdk_kms::error::SdkError;
use aws_sdk_kms::operation::sign::SignError;
use aws_sdk_kms::types::SigningAlgorithmSpec;
use miden_node_utils::signer::BlockSigner;
use miden_protocol::block::BlockHeader;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::{PublicKey, Signature};
use miden_protocol::crypto::hash::keccak::Keccak256;
use miden_protocol::utils::serde::{Deserializable, DeserializationError, Serializable};

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
    #[error("invalid signature format")]
    SignatureFormatError(#[source] DeserializationError),
    /// The KMS backend returned a signature that was not able to be verified.
    #[error("invalid signature")]
    InvalidSignature,
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

        // Extract the raw SEC1 public key bytes from the SPKI DER encoding and decode as a
        // Miden public key.
        let sec1_bytes = extract_sec1_from_spki_der(spki_der)?;
        let pub_key = PublicKey::read_from_bytes(sec1_bytes)?;
        Ok(Self { key_id, pub_key, client })
    }
}

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
        let sig_bytes = parse_der_ecdsa_signature(sig_der.as_ref())
            .map_err(KmsSignerError::SignatureFormatError)?;
        let sig = Signature::from_sec1_bytes_and_recovery_id(sig_bytes, recovery_id)
            .map_err(KmsSignerError::SignatureFormatError)?;

        // Check the returned signature.
        if sig.verify(header.commitment(), &self.pub_key) {
            Ok(sig)
        } else {
            Err(KmsSignerError::InvalidSignature)
        }
    }

    fn public_key(&self) -> PublicKey {
        self.pub_key.clone()
    }
}

// HELPERS
// ================================================================================================

/// Extracts the raw SEC1 public key bytes from a DER-encoded `SubjectPublicKeyInfo` (SPKI)
/// structure.
///
/// SPKI DER layout:
///   SEQUENCE {
///     SEQUENCE { algorithm OID, parameters }
///     BIT STRING { 0x00 (unused bits), <SEC1 point bytes> }
///   }
fn extract_sec1_from_spki_der(der: &[u8]) -> Result<&[u8], DeserializationError> {
    // Skip the outer SEQUENCE tag + length.
    let rest = skip_der_tag_and_length(der, 0x30)?;
    // Skip the inner SEQUENCE (algorithm identifier) tag + length + content.
    let rest = skip_der_tlv(rest, 0x30)?;
    // Parse the BIT STRING.
    let content = read_der_content(rest, 0x03)?;
    // The first byte of BIT STRING content is the "unused bits" count (must be 0 for keys).
    if content.is_empty() || content[0] != 0 {
        return Err(DeserializationError::InvalidValue(
            "Invalid SPKI BIT STRING padding".to_string(),
        ));
    }
    Ok(&content[1..])
}

/// Parses a DER-encoded ECDSA signature (ASN.1: SEQUENCE { INTEGER r, INTEGER s }) into a
/// 64-byte r||s array.
fn parse_der_ecdsa_signature(der: &[u8]) -> Result<[u8; 64], DeserializationError> {
    let rest = skip_der_tag_and_length(der, 0x30)?;
    let (r_bytes, rest) = read_der_integer(rest)?;
    let (s_bytes, _) = read_der_integer(rest)?;

    let mut out = [0u8; 64];
    copy_integer_to_fixed(r_bytes, &mut out[..32])?;
    copy_integer_to_fixed(s_bytes, &mut out[32..])?;
    Ok(out)
}

/// Copies a variable-length big-endian integer into a fixed-size buffer, right-aligned.
/// Strips leading zero padding if present.
fn copy_integer_to_fixed(src: &[u8], dst: &mut [u8]) -> Result<(), DeserializationError> {
    // Strip leading zeros.
    let src = match src.iter().position(|&b| b != 0) {
        Some(pos) => &src[pos..],
        None => &[0],
    };
    if src.len() > dst.len() {
        return Err(DeserializationError::InvalidValue(
            "DER integer too large for target".to_string(),
        ));
    }
    let offset = dst.len() - src.len();
    dst[offset..].copy_from_slice(src);
    Ok(())
}

/// Skips a DER tag byte and its length field, returning the content slice.
fn skip_der_tag_and_length(data: &[u8], expected_tag: u8) -> Result<&[u8], DeserializationError> {
    if data.is_empty() || data[0] != expected_tag {
        return Err(DeserializationError::InvalidValue(format!(
            "Expected DER tag 0x{expected_tag:02x}, got 0x{:02x}",
            data.first().copied().unwrap_or(0)
        )));
    }
    let (_, rest) = read_der_length(&data[1..])?;
    Ok(rest)
}

/// Skips an entire DER TLV (tag + length + value), returning the remaining data after it.
fn skip_der_tlv(data: &[u8], expected_tag: u8) -> Result<&[u8], DeserializationError> {
    if data.is_empty() || data[0] != expected_tag {
        return Err(DeserializationError::InvalidValue(format!(
            "Expected DER tag 0x{expected_tag:02x}, got 0x{:02x}",
            data.first().copied().unwrap_or(0)
        )));
    }
    let (len, rest) = read_der_length(&data[1..])?;
    if rest.len() < len {
        return Err(DeserializationError::InvalidValue("DER content truncated".to_string()));
    }
    Ok(&rest[len..])
}

/// Reads a DER element's content bytes given its expected tag.
fn read_der_content(data: &[u8], expected_tag: u8) -> Result<&[u8], DeserializationError> {
    if data.is_empty() || data[0] != expected_tag {
        return Err(DeserializationError::InvalidValue(format!(
            "Expected DER tag 0x{expected_tag:02x}, got 0x{:02x}",
            data.first().copied().unwrap_or(0)
        )));
    }
    let (len, rest) = read_der_length(&data[1..])?;
    if rest.len() < len {
        return Err(DeserializationError::InvalidValue("DER content truncated".to_string()));
    }
    Ok(&rest[..len])
}

/// Reads a DER INTEGER element, returning (value bytes, remaining data).
fn read_der_integer(data: &[u8]) -> Result<(&[u8], &[u8]), DeserializationError> {
    if data.is_empty() || data[0] != 0x02 {
        return Err(DeserializationError::InvalidValue("Expected DER INTEGER tag".to_string()));
    }
    let (len, rest) = read_der_length(&data[1..])?;
    if rest.len() < len {
        return Err(DeserializationError::InvalidValue("DER INTEGER truncated".to_string()));
    }
    Ok((&rest[..len], &rest[len..]))
}

/// Reads a DER length field, returning (length value, remaining data after length).
fn read_der_length(data: &[u8]) -> Result<(usize, &[u8]), DeserializationError> {
    if data.is_empty() {
        return Err(DeserializationError::InvalidValue("DER length missing".to_string()));
    }
    if data[0] < 0x80 {
        Ok((data[0] as usize, &data[1..]))
    } else {
        let num_bytes = (data[0] & 0x7f) as usize;
        if num_bytes == 0 || num_bytes > 4 || data.len() < 1 + num_bytes {
            return Err(DeserializationError::InvalidValue(
                "Invalid DER length encoding".to_string(),
            ));
        }
        let mut len = 0usize;
        for &b in &data[1..=num_bytes] {
            len = (len << 8) | b as usize;
        }
        Ok((len, &data[1 + num_bytes..]))
    }
}
