//! Sealing of transaction inputs against the validator set's shared encryption key.
//!
//! This module is the single definition of the associated-data transcript, so the sealing side
//! (clients and the node's own submitters) and the unsealing side (the validator) cannot drift.
//! A drift would not fail to compile: it would reject every submission at runtime with an opaque
//! AEAD error, so the transcript is pinned by a golden vector in the tests below.

use miden_protocol::Word;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::{
    PublicKey as ValidatorPublicKey,
    Signature as ValidatorSignature,
};
use miden_protocol::crypto::dsa::eddsa_25519_sha512::PublicKey as EncryptionPublicKey;
use miden_protocol::crypto::ies::SealingKey;
use miden_protocol::transaction::TransactionId;
use miden_protocol::utils::serde::{Deserializable, Serializable};

use crate::generated as proto;

/// Domain tag prefixed to the associated data of sealed transaction inputs.
///
/// Separates this transcript from every other use of the same key material, in particular from the
/// key attestation signed with the validator's signing key.
pub const TX_INPUT_SEAL_DOMAIN: &[u8] = b"MIDEN_TX_INPUT_SEAL_V1";

/// Domain tag prefixed to the validator-signed encryption key payload.
pub const ATTESTATION_DOMAIN: &[u8] = b"MIDEN_TX_ENCRYPTION_KEY_ATTESTATION_V1";

/// Upper bound on the length of an encryption key identifier.
///
/// Key identifiers are 4 bytes today (the leading bytes of the public key commitment). The bound
/// exists so that a hostile or misconfigured key endpoint cannot drive an unbounded allocation, and
/// so that the length cast in the transcript cannot overflow.
pub const MAX_KEY_ID_LEN: usize = 64;

/// Wire identifier of the only IES scheme the node currently supports.
const SCHEME_X25519_XCHACHA20_POLY1305: u32 = 1;

// ENCRYPTION KEY
// ================================================================================================

/// Encryption schemes supported by transaction input submission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum TransactionEncryptionScheme {
    /// X25519 key agreement with XChaCha20-Poly1305 authenticated encryption.
    X25519XChaCha20Poly1305 = SCHEME_X25519_XCHACHA20_POLY1305,
}

impl TransactionEncryptionScheme {
    /// Returns the integer used for this scheme on the wire and in signed transcripts.
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    /// Returns the protobuf enum value for this scheme.
    pub const fn as_i32(self) -> i32 {
        self as i32
    }
}

impl TryFrom<i32> for TransactionEncryptionScheme {
    type Error = TransactionEncryptionKeyError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Err(TransactionEncryptionKeyError::UnspecifiedScheme),
            1 => Ok(Self::X25519XChaCha20Poly1305),
            other => Err(TransactionEncryptionKeyError::UnsupportedScheme(other)),
        }
    }
}

/// Public metadata for a scheduled transaction encryption key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NextEncryptionKeyInfo {
    /// Encryption scheme for the scheduled key.
    pub scheme: TransactionEncryptionScheme,
    /// Opaque identifier of the scheduled key.
    pub key_id: Vec<u8>,
    /// Encoded public key.
    pub public_key: Vec<u8>,
    /// Block at which the scheduled key becomes current.
    pub rotation_block_num: u32,
}

/// Public metadata for the transaction encryption key served by a validator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionEncryptionKeyInfo {
    /// Encryption scheme for the current key.
    pub scheme: TransactionEncryptionScheme,
    /// Opaque identifier of the current key.
    pub key_id: Vec<u8>,
    /// Encoded public key.
    pub public_key: Vec<u8>,
    /// Scheduled replacement key, when one exists.
    pub next_key: Option<NextEncryptionKeyInfo>,
}

impl TransactionEncryptionKeyInfo {
    /// Returns the commitment a validator signs to attest this key for one network.
    pub fn attestation_commitment(&self, genesis_commitment: Word) -> Word {
        attestation_commitment(
            self.scheme,
            &self.key_id,
            genesis_commitment,
            &self.public_key,
            self.next_key.as_ref(),
        )
    }
}

/// Trusted chain state used to verify a served transaction encryption key.
#[derive(Debug, Clone, Copy)]
pub struct TrustedTransactionEncryptionState<'a> {
    genesis_commitment: Word,
    validator_signing_keys: &'a [ValidatorPublicKey],
}

impl<'a> TrustedTransactionEncryptionState<'a> {
    /// Creates trusted state from a genesis commitment and its validator signing keys.
    pub const fn new(
        genesis_commitment: Word,
        validator_signing_keys: &'a [ValidatorPublicKey],
    ) -> Self {
        Self {
            genesis_commitment,
            validator_signing_keys,
        }
    }
}

/// A transaction encryption key whose attestation matches trusted chain state.
#[derive(Debug, Clone)]
pub struct VerifiedTransactionEncryptionKey {
    info: TransactionEncryptionKeyInfo,
    public_key: EncryptionPublicKey,
    genesis_commitment: Word,
}

impl VerifiedTransactionEncryptionKey {
    /// Returns the verified key metadata.
    pub const fn info(&self) -> &TransactionEncryptionKeyInfo {
        &self.info
    }

    /// Returns the decoded encryption public key.
    pub const fn public_key(&self) -> &EncryptionPublicKey {
        &self.public_key
    }

    /// Returns the network genesis commitment covered by the attestation.
    pub const fn genesis_commitment(&self) -> Word {
        self.genesis_commitment
    }
}

// ASSOCIATED DATA
// ================================================================================================

/// Builds the associated data authenticating a sealed set of transaction inputs.
///
/// This is the single definition of the transcript. Both sides derive it independently and it is
/// never transmitted, so a mismatch surfaces as an authentication failure rather than as accepted
/// but unauthenticated data.
///
/// The layout is `TX_INPUT_SEAL_DOMAIN || scheme || len(key_id) || key_id || genesis_commitment ||
/// transaction_id`, where the scheme and the length prefix are 4 bytes little-endian. The domain tag
/// is a fixed-width constant, `scheme` is fixed-width, `key_id` is length-prefixed and the two
/// trailing fields are a fixed 32 bytes each, so no two distinct inputs produce the same transcript.
///
/// Each binding serves a purpose:
/// - `scheme` and `key_id` tie the blob to one key, so inputs sealed against a retired key fail to
///   authenticate rather than silently decrypting.
/// - `genesis_commitment` ties the blob to one network. This matters in practice because every
///   development stack shares the same insecure default key, so without it a blob captured on one
///   network would replay onto another.
/// - `transaction_id` ties the blob to one transaction, so a captured blob cannot be replayed onto a
///   different transaction.
///
/// Deliberately absent is the serialized transaction. The RPC rebuilds `ProvenTransaction` with
/// output-note decorators stripped before forwarding a submission, so binding those bytes would
/// reject every relayed transaction. The transaction id is invariant under that rebuild, which is
/// why it is bound instead.
pub fn transaction_inputs_associated_data(
    scheme: u32,
    key_id: &[u8],
    genesis_commitment: Word,
    tx_id: TransactionId,
) -> Vec<u8> {
    let genesis_commitment = genesis_commitment.to_bytes();
    let tx_id = tx_id.as_word().to_bytes();
    let mut transcript = Vec::with_capacity(
        TX_INPUT_SEAL_DOMAIN.len()
            + 2 * size_of::<u32>()
            + key_id.len()
            + genesis_commitment.len()
            + tx_id.len(),
    );
    transcript.extend_from_slice(TX_INPUT_SEAL_DOMAIN);
    transcript.extend_from_slice(&scheme.to_le_bytes());
    // Callers bound `key_id` to MAX_KEY_ID_LEN, so this cast cannot realistically fail. Saturate
    // rather than panic anyway: this runs inside a request handler on the validator.
    let key_id_len = u32::try_from(key_id.len()).unwrap_or(u32::MAX);
    transcript.extend_from_slice(&key_id_len.to_le_bytes());
    transcript.extend_from_slice(key_id);
    transcript.extend_from_slice(&genesis_commitment);
    transcript.extend_from_slice(&tx_id);
    transcript
}

// ERRORS
// ================================================================================================

/// Failure to decode or verify a served transaction encryption key.
#[derive(Debug, thiserror::Error)]
pub enum TransactionEncryptionKeyError {
    #[error("encryption key scheme is unspecified")]
    UnspecifiedScheme,
    #[error("unsupported encryption key scheme {0}")]
    UnsupportedScheme(i32),
    #[error("{field} is empty")]
    EmptyKeyId { field: &'static str },
    #[error("{field} is {len} bytes, which exceeds the maximum of {MAX_KEY_ID_LEN}")]
    KeyIdTooLong { field: &'static str, len: usize },
    #[error("invalid {field}")]
    InvalidEncryptionPublicKey {
        field: &'static str,
        #[source]
        source: miden_protocol::utils::serde::DeserializationError,
    },
    #[error("trusted validator signing keys are empty")]
    NoTrustedValidatorKeys,
    #[error("transaction encryption key has no validator attestations")]
    NoAttestations,
    #[error("transaction encryption key has no attestation from a trusted validator")]
    NoTrustedAttestation,
    #[error("trusted validator attestation does not cover the transaction encryption key")]
    InvalidAttestation,
}

/// Failure to seal transaction inputs.
#[derive(Debug, thiserror::Error)]
pub enum TransactionInputSealError {
    #[error("failed to seal the transaction inputs")]
    Seal(#[source] miden_protocol::crypto::ies::IesError),
}

// ATTESTATION
// ================================================================================================

/// Verifies a served transaction encryption key against trusted chain state.
pub fn verify_transaction_encryption_key(
    key: proto::submission::TransactionEncryptionKey,
    trusted: TrustedTransactionEncryptionState<'_>,
) -> Result<VerifiedTransactionEncryptionKey, TransactionEncryptionKeyError> {
    if trusted.validator_signing_keys.is_empty() {
        return Err(TransactionEncryptionKeyError::NoTrustedValidatorKeys);
    }
    if key.attestations.is_empty() {
        return Err(TransactionEncryptionKeyError::NoAttestations);
    }

    let (info, public_key) = decode_key_info(&key)?;
    let commitment = info.attestation_commitment(trusted.genesis_commitment);
    let mut found_trusted_signer = false;

    for attestation in key.attestations {
        let Some(validator_public_key) = attestation.validator_public_key else {
            continue;
        };
        let Ok(validator_public_key) = validator_public_key.try_into() else {
            continue;
        };

        if !trusted.validator_signing_keys.contains(&validator_public_key) {
            continue;
        }
        found_trusted_signer = true;

        let Some(signature) = attestation.signature else {
            continue;
        };
        let Ok(signature): Result<ValidatorSignature, _> = signature.try_into() else {
            continue;
        };
        if signature.verify(commitment, &validator_public_key) {
            return Ok(VerifiedTransactionEncryptionKey {
                info,
                public_key,
                genesis_commitment: trusted.genesis_commitment,
            });
        }
    }

    if found_trusted_signer {
        Err(TransactionEncryptionKeyError::InvalidAttestation)
    } else {
        Err(TransactionEncryptionKeyError::NoTrustedAttestation)
    }
}

/// Decodes all key fields which are covered by the validator attestation.
fn decode_key_info(
    key: &proto::submission::TransactionEncryptionKey,
) -> Result<(TransactionEncryptionKeyInfo, EncryptionPublicKey), TransactionEncryptionKeyError> {
    let scheme = TransactionEncryptionScheme::try_from(key.scheme)?;
    validate_key_id(&key.key_id, "encryption key id")?;
    let public_key = EncryptionPublicKey::read_from_bytes(&key.public_key).map_err(|source| {
        TransactionEncryptionKeyError::InvalidEncryptionPublicKey {
            field: "encryption public key",
            source,
        }
    })?;

    let next_key = key
        .next_key
        .as_ref()
        .map(|next| {
            let scheme = TransactionEncryptionScheme::try_from(next.scheme)?;
            validate_key_id(&next.key_id, "next encryption key id")?;
            EncryptionPublicKey::read_from_bytes(&next.public_key).map_err(|source| {
                TransactionEncryptionKeyError::InvalidEncryptionPublicKey {
                    field: "next encryption public key",
                    source,
                }
            })?;

            Ok(NextEncryptionKeyInfo {
                scheme,
                key_id: next.key_id.clone(),
                public_key: next.public_key.clone(),
                rotation_block_num: next.rotation_block_num,
            })
        })
        .transpose()?;

    Ok((
        TransactionEncryptionKeyInfo {
            scheme,
            key_id: key.key_id.clone(),
            public_key: key.public_key.clone(),
            next_key,
        },
        public_key,
    ))
}

/// Validates a key identifier before it is used in a transcript or allocation.
fn validate_key_id(
    key_id: &[u8],
    field: &'static str,
) -> Result<(), TransactionEncryptionKeyError> {
    if key_id.is_empty() {
        return Err(TransactionEncryptionKeyError::EmptyKeyId { field });
    }
    if key_id.len() > MAX_KEY_ID_LEN {
        return Err(TransactionEncryptionKeyError::KeyIdTooLong { field, len: key_id.len() });
    }
    Ok(())
}

/// Computes the validator-signed commitment over transaction encryption key metadata.
fn attestation_commitment(
    scheme: TransactionEncryptionScheme,
    key_id: &[u8],
    genesis_commitment: Word,
    public_key: &[u8],
    next_key: Option<&NextEncryptionKeyInfo>,
) -> Word {
    let genesis_commitment = genesis_commitment.to_bytes();
    let next_key_size = next_key
        .map(|next| 3 * size_of::<u32>() + next.key_id.len() + next.public_key.len())
        .unwrap_or_default();
    let mut payload = Vec::with_capacity(
        ATTESTATION_DOMAIN.len()
            + 3 * size_of::<u32>()
            + key_id.len()
            + genesis_commitment.len()
            + public_key.len()
            + next_key_size,
    );
    payload.extend_from_slice(ATTESTATION_DOMAIN);
    payload.extend_from_slice(&scheme.as_u32().to_le_bytes());
    extend_with_length_prefixed(&mut payload, key_id, "key id");
    payload.extend_from_slice(&genesis_commitment);
    extend_with_length_prefixed(&mut payload, public_key, "public key");
    if let Some(next) = next_key {
        payload.extend_from_slice(&next.scheme.as_u32().to_le_bytes());
        extend_with_length_prefixed(&mut payload, &next.key_id, "next key id");
        extend_with_length_prefixed(&mut payload, &next.public_key, "next public key");
        payload.extend_from_slice(&next.rotation_block_num.to_le_bytes());
    }
    miden_protocol::Hasher::hash(&payload)
}

/// Appends a length-prefixed field to the attestation transcript.
fn extend_with_length_prefixed(payload: &mut Vec<u8>, field: &[u8], name: &str) {
    let len = u32::try_from(field.len())
        .unwrap_or_else(|_| panic!("{name} length must fit in u32"))
        .to_le_bytes();
    payload.extend_from_slice(&len);
    payload.extend_from_slice(field);
}

// SEALER
// ================================================================================================

/// Seals transaction inputs against the validator set's shared encryption key.
///
/// Built from a verified transaction encryption key and reusable for any number of transactions.
/// Holding one avoids re-fetching the key per submission; callers should discard it when the
/// validator reports an unknown key ID.
#[derive(Debug, Clone)]
pub struct TransactionInputsSealer {
    scheme: TransactionEncryptionScheme,
    key_id: Vec<u8>,
    sealing_key: SealingKey,
    genesis_commitment: Word,
}

impl TransactionInputsSealer {
    /// Builds a sealer from a key whose validator attestation has already been verified.
    pub fn new(key: VerifiedTransactionEncryptionKey) -> Self {
        Self {
            scheme: key.info.scheme,
            key_id: key.info.key_id,
            sealing_key: SealingKey::X25519XChaCha20Poly1305(key.public_key),
            genesis_commitment: key.genesis_commitment,
        }
    }

    /// The identifier of the key this sealer seals against.
    pub fn key_id(&self) -> &[u8] {
        &self.key_id
    }

    /// Seals `transaction_inputs` for the transaction identified by `tx_id`.
    ///
    /// `transaction_inputs` must be the encoding of
    /// [`miden_protocol::transaction::TransactionInputs::to_bytes`].
    ///
    /// Each call draws a fresh ephemeral key, so sealing the same inputs twice is safe and yields
    /// different ciphertexts.
    pub fn seal(
        &self,
        tx_id: TransactionId,
        transaction_inputs: &[u8],
    ) -> Result<proto::submission::SealedTransactionInputs, TransactionInputSealError> {
        let associated_data = transaction_inputs_associated_data(
            self.scheme.as_u32(),
            &self.key_id,
            self.genesis_commitment,
            tx_id,
        );
        let sealed = self
            .sealing_key
            .seal_bytes_with_associated_data(&mut rand::rng(), transaction_inputs, &associated_data)
            .map_err(TransactionInputSealError::Seal)?;

        Ok(proto::submission::SealedTransactionInputs {
            key_id: self.key_id.clone(),
            ciphertext: sealed.to_bytes(),
        })
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey;
    use miden_protocol::crypto::dsa::eddsa_25519_sha512::KeyExchangeKey;

    use super::*;

    const TEST_KEY_ID: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];

    fn genesis() -> Word {
        Word::from([1u32, 2, 3, 4])
    }

    fn tx_id(seed: u32) -> TransactionId {
        TransactionId::new(
            Word::from([seed, 0, 0, 0]),
            Word::from([0, seed, 0, 0]),
            Word::from([0, 0, seed, 0]),
            Word::from([0, 0, 0, seed]),
        )
    }

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::read_from_bytes(&[seed; 32]).expect("test signing key should decode")
    }

    fn unsigned_encryption_key() -> proto::submission::TransactionEncryptionKey {
        proto::submission::TransactionEncryptionKey {
            scheme: TransactionEncryptionScheme::X25519XChaCha20Poly1305.as_i32(),
            key_id: TEST_KEY_ID.to_vec(),
            public_key: KeyExchangeKey::read_from_bytes(&[7u8; 32])
                .unwrap()
                .public_key()
                .to_bytes(),
            attestations: Vec::new(),
            next_key: None,
        }
    }

    fn signed_encryption_key(
        signer: &SigningKey,
        genesis_commitment: Word,
    ) -> proto::submission::TransactionEncryptionKey {
        let mut key = unsigned_encryption_key();
        let (info, _) = decode_key_info(&key).unwrap();
        key.attestations = vec![proto::submission::ValidatorKeyAttestation {
            validator_public_key: Some(signer.public_key().into()),
            signature: Some(signer.sign(info.attestation_commitment(genesis_commitment)).into()),
        }];
        key
    }

    /// A key signed by the validator committed in trusted chain state verifies.
    #[test]
    fn verifies_trusted_validator_attestation() {
        let signer = signing_key(1);
        let trusted_keys = [signer.public_key()];
        let key = signed_encryption_key(&signer, genesis());

        let verified = verify_transaction_encryption_key(
            key,
            TrustedTransactionEncryptionState::new(genesis(), &trusted_keys),
        )
        .unwrap();

        assert_eq!(verified.info().key_id, TEST_KEY_ID);
        assert_eq!(verified.info().scheme, TransactionEncryptionScheme::X25519XChaCha20Poly1305);
        assert_eq!(verified.genesis_commitment(), genesis());
    }

    /// An untrusted RPC cannot omit or rely on a malformed validator attestation.
    #[test]
    fn rejects_missing_and_malformed_attestations() {
        let signer = signing_key(1);
        let trusted_keys = [signer.public_key()];
        let trusted = TrustedTransactionEncryptionState::new(genesis(), &trusted_keys);

        assert_matches!(
            verify_transaction_encryption_key(unsigned_encryption_key(), trusted),
            Err(TransactionEncryptionKeyError::NoAttestations)
        );

        let mut malformed_key = signed_encryption_key(&signer, genesis());
        malformed_key.attestations[0]
            .validator_public_key
            .as_mut()
            .unwrap()
            .encoded
            .clear();
        assert_matches!(
            verify_transaction_encryption_key(malformed_key, trusted),
            Err(TransactionEncryptionKeyError::NoTrustedAttestation)
        );

        let mut malformed_signature = signed_encryption_key(&signer, genesis());
        malformed_signature.attestations[0].signature.as_mut().unwrap().encoded.clear();
        assert_matches!(
            verify_transaction_encryption_key(malformed_signature, trusted),
            Err(TransactionEncryptionKeyError::InvalidAttestation)
        );
    }

    /// A malformed attestation does not hide a later valid attestation.
    #[test]
    fn skips_malformed_attestations() {
        let signer = signing_key(1);
        let trusted_keys = [signer.public_key()];
        let mut key = signed_encryption_key(&signer, genesis());
        key.attestations.insert(
            0,
            proto::submission::ValidatorKeyAttestation {
                validator_public_key: None,
                signature: None,
            },
        );

        verify_transaction_encryption_key(
            key,
            TrustedTransactionEncryptionState::new(genesis(), &trusted_keys),
        )
        .unwrap();
    }

    /// A valid signature does not help when its signer is absent from trusted chain state.
    #[test]
    fn rejects_untrusted_validator_attestation() {
        let trusted_signer = signing_key(1);
        let untrusted_signer = signing_key(2);
        let trusted_keys = [trusted_signer.public_key()];

        assert_matches!(
            verify_transaction_encryption_key(
                signed_encryption_key(&untrusted_signer, genesis()),
                TrustedTransactionEncryptionState::new(genesis(), &trusted_keys),
            ),
            Err(TransactionEncryptionKeyError::NoTrustedAttestation)
        );
    }

    /// Every served key field and the network identity are covered by the signature.
    #[test]
    fn rejects_changed_attested_fields() {
        let signer = signing_key(1);
        let trusted_keys = [signer.public_key()];
        let trusted = TrustedTransactionEncryptionState::new(genesis(), &trusted_keys);
        let key = signed_encryption_key(&signer, genesis());

        let mut changed_scheme = key.clone();
        changed_scheme.scheme = 0;
        let mut changed_key_id = key.clone();
        changed_key_id.key_id[0] ^= 1;
        let mut changed_public_key = key.clone();
        changed_public_key.public_key =
            KeyExchangeKey::read_from_bytes(&[8u8; 32]).unwrap().public_key().to_bytes();
        let mut injected_next_key = key.clone();
        injected_next_key.next_key = Some(proto::submission::NextTransactionEncryptionKey {
            scheme: key.scheme,
            key_id: vec![1, 2, 3, 4],
            public_key: KeyExchangeKey::read_from_bytes(&[9u8; 32])
                .unwrap()
                .public_key()
                .to_bytes(),
            rotation_block_num: 100,
        });

        for changed in [changed_scheme, changed_key_id, changed_public_key, injected_next_key] {
            assert!(verify_transaction_encryption_key(changed, trusted).is_err());
        }

        assert_matches!(
            verify_transaction_encryption_key(
                key,
                TrustedTransactionEncryptionState::new(Word::from([9u32, 9, 9, 9]), &trusted_keys),
            ),
            Err(TransactionEncryptionKeyError::InvalidAttestation)
        );
    }

    /// Key metadata is bounded and decoded before it can become domain state.
    #[test]
    fn rejects_invalid_key_metadata() {
        let signer = signing_key(1);
        let trusted_keys = [signer.public_key()];
        let trusted = TrustedTransactionEncryptionState::new(genesis(), &trusted_keys);

        let mut empty_key_id = signed_encryption_key(&signer, genesis());
        empty_key_id.key_id.clear();
        assert_matches!(
            verify_transaction_encryption_key(empty_key_id, trusted),
            Err(TransactionEncryptionKeyError::EmptyKeyId { .. })
        );

        let mut oversized_key_id = signed_encryption_key(&signer, genesis());
        oversized_key_id.key_id = vec![0; MAX_KEY_ID_LEN + 1];
        assert_matches!(
            verify_transaction_encryption_key(oversized_key_id, trusted),
            Err(TransactionEncryptionKeyError::KeyIdTooLong { .. })
        );

        let mut invalid_public_key = signed_encryption_key(&signer, genesis());
        invalid_public_key.public_key.clear();
        assert_matches!(
            verify_transaction_encryption_key(invalid_public_key, trusted),
            Err(TransactionEncryptionKeyError::InvalidEncryptionPublicKey { .. })
        );
    }

    /// Pins the transcript byte-for-byte, which also pins *which* fields it binds.
    ///
    /// Both sides derive the transcript through this one function, so a change to it would pass
    /// every other test in the workspace and surface only as every submission on the network failing
    /// to authenticate. This vector is the only thing that catches that.
    #[test]
    fn associated_data_is_stable() {
        let ad = transaction_inputs_associated_data(1, &TEST_KEY_ID, genesis(), tx_id(10));

        let mut expected = Vec::new();
        expected.extend_from_slice(b"MIDEN_TX_INPUT_SEAL_V1");
        expected.extend_from_slice(&1u32.to_le_bytes());
        expected.extend_from_slice(&4u32.to_le_bytes());
        expected.extend_from_slice(&TEST_KEY_ID);
        expected.extend_from_slice(&genesis().to_bytes());
        expected.extend_from_slice(&tx_id(10).as_word().to_bytes());

        assert_eq!(ad, expected);
        // 22-byte tag + 4 scheme + 4 length + 4 key id + 32 genesis + 32 transaction id.
        assert_eq!(ad.len(), 98);
    }
}
