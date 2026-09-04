use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use golden_ehtdh1::wire::{from_wire_bytes, to_wire_bytes};
use golden_ehtdh1::{Ciphertext, Combiner, DecryptionShare, SealingKey};
use golden_halo2curves::golden_group::Secp256k1GoldenGroup;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::PublicKey;
use miden_protocol::transaction::TransactionId;
use miden_protocol::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use rand_core_06::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::{GoldenOperatorKey, StorageKeyEpoch};

/// Version of the first private record context and encryption format.
pub const PRIVATE_RECORD_FORMAT_V1: u32 = 1;

const CONTEXT_DOMAIN_V1: &[u8] = b"miden-private-record-context-v1";
const PRIVATE_RECORD_BUNDLE_MAGIC: &[u8] = b"miden-private-record-bundle-v1";
pub(crate) const CONTENT_KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 24;
const TAG_BYTES: usize = 16;
const VALIDATOR_ID_BYTES: usize = 33;

type StorageGroup = Secp256k1GoldenGroup;

/// Identifier for the chain that owns a private record.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PrivateRecordChainId([u8; 32]);

impl PrivateRecordChainId {
    /// Creates a chain identifier from its canonical bytes.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the canonical chain identifier bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Global identity of one validator's encrypted record for a transaction.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PrivateRecordId {
    transaction_id: TransactionId,
    validator_id: [u8; VALIDATOR_ID_BYTES],
}

impl PrivateRecordId {
    /// Creates a record identity from a transaction and validator signing key.
    pub fn new(transaction_id: TransactionId, validator_public_key: &PublicKey) -> Self {
        let validator_id = validator_public_key
            .to_bytes()
            .try_into()
            .expect("validator public keys have a fixed canonical length");
        Self { transaction_id, validator_id }
    }

    /// Rebuilds a record identity from its canonical fields.
    pub fn from_parts(
        transaction_id: TransactionId,
        validator_id: [u8; VALIDATOR_ID_BYTES],
    ) -> Result<Self, PrivateRecordError> {
        PublicKey::read_from_bytes(&validator_id)
            .map_err(PrivateRecordError::InvalidValidatorId)?;
        Ok(Self { transaction_id, validator_id })
    }

    /// Returns the transaction identifier.
    pub const fn transaction_id(&self) -> TransactionId {
        self.transaction_id
    }

    /// Returns the canonical validator signing public key bytes.
    pub const fn validator_id(&self) -> &[u8; VALIDATOR_ID_BYTES] {
        &self.validator_id
    }
}

/// Values bound to one private record and its Golden decryption shares.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivateRecordContext {
    chain_id: PrivateRecordChainId,
    key_epoch: StorageKeyEpoch,
    transaction_id: TransactionId,
}

impl PrivateRecordContext {
    /// Creates a schema version 1 context.
    pub const fn new(
        chain_id: PrivateRecordChainId,
        key_epoch: StorageKeyEpoch,
        transaction_id: TransactionId,
    ) -> Self {
        Self { chain_id, key_epoch, transaction_id }
    }

    /// Returns the chain identifier.
    pub const fn chain_id(&self) -> PrivateRecordChainId {
        self.chain_id
    }

    /// Returns the storage key epoch.
    pub const fn key_epoch(&self) -> StorageKeyEpoch {
        self.key_epoch
    }

    /// Returns the transaction identifier.
    pub const fn transaction_id(&self) -> TransactionId {
        self.transaction_id
    }

    /// Returns the record format version.
    pub const fn format_version(&self) -> u32 {
        PRIVATE_RECORD_FORMAT_V1
    }

    /// Returns the canonical context used by the record cipher and Golden.
    pub fn to_bytes(self) -> Vec<u8> {
        let transaction_id = self.transaction_id.to_bytes();
        let mut context = Vec::with_capacity(CONTEXT_DOMAIN_V1.len() + 3 * 32 + size_of::<u32>());
        context.extend_from_slice(CONTEXT_DOMAIN_V1);
        context.extend_from_slice(self.chain_id.as_bytes());
        context.extend_from_slice(self.key_epoch.as_bytes());
        context.extend_from_slice(&transaction_id);
        context.extend_from_slice(&PRIVATE_RECORD_FORMAT_V1.to_be_bytes());
        context
    }

    /// Parses a canonical schema version 1 context produced by [`Self::to_bytes`].
    ///
    /// Rejects any input whose domain tag, length, or format version differ from schema
    /// version 1, or whose transaction id is not canonical.
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, PrivateRecordError> {
        let malformed = || PrivateRecordError::MalformedDecryptionContext;
        let (domain, rest) =
            bytes.split_at_checked(CONTEXT_DOMAIN_V1.len()).ok_or_else(malformed)?;
        let (chain_id, rest) = rest.split_at_checked(32).ok_or_else(malformed)?;
        let (key_epoch, rest) = rest.split_at_checked(32).ok_or_else(malformed)?;
        let (transaction_id, version) = rest.split_at_checked(32).ok_or_else(malformed)?;
        if domain != CONTEXT_DOMAIN_V1 || version != PRIVATE_RECORD_FORMAT_V1.to_be_bytes() {
            return Err(malformed());
        }
        let transaction_id =
            TransactionId::read_from_bytes(transaction_id).map_err(|_error| malformed())?;
        Ok(Self::new(
            PrivateRecordChainId::new(chain_id.try_into().expect("split yields 32 bytes")),
            StorageKeyEpoch::new(key_epoch.try_into().expect("split yields 32 bytes")),
            transaction_id,
        ))
    }
}

/// Exact record values that an operator must approve before issuing a share.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivateRecordShareRequest {
    record_id: PrivateRecordId,
    key_epoch: StorageKeyEpoch,
    context: Vec<u8>,
}

impl PrivateRecordShareRequest {
    /// Creates a request for one transaction, epoch, and canonical context.
    pub fn new(record_id: PrivateRecordId, key_epoch: StorageKeyEpoch, context: Vec<u8>) -> Self {
        Self { record_id, key_epoch, context }
    }

    /// Creates a request from one checked stored record.
    pub fn for_record(record: &StoredPrivateRecord) -> Self {
        let context = record.context();
        Self::new(record.record_id(), context.key_epoch(), context.to_bytes())
    }

    /// Returns the requested transaction identifier.
    pub const fn transaction_id(&self) -> TransactionId {
        self.record_id.transaction_id()
    }

    /// Returns the requested private-record identifier.
    pub const fn record_id(&self) -> PrivateRecordId {
        self.record_id
    }

    /// Returns the requested storage key epoch.
    pub const fn key_epoch(&self) -> StorageKeyEpoch {
        self.key_epoch
    }

    /// Returns the exact requested decryption context.
    pub fn context(&self) -> &[u8] {
        &self.context
    }
}

/// Public Golden key used to seal private records for one epoch.
#[derive(Clone, Debug)]
pub struct PrivateRecordSealer {
    key_epoch: StorageKeyEpoch,
    setup_context_id: [u8; 32],
    sealing_key: SealingKey<StorageGroup>,
}

impl PrivateRecordSealer {
    /// Creates a sealer from a validated operator key without copying its secret share.
    pub fn from_operator_key(operator_key: &GoldenOperatorKey) -> Self {
        Self {
            key_epoch: operator_key.key_epoch(),
            setup_context_id: operator_key.setup_context_id(),
            sealing_key: operator_key.sealing_key().clone(),
        }
    }

    /// Returns the storage-key epoch used to seal records.
    pub fn key_epoch(&self) -> StorageKeyEpoch {
        self.key_epoch
    }

    /// Encrypts a record and wraps only its fresh content key with Golden.
    pub fn seal<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        record_id: PrivateRecordId,
        context: PrivateRecordContext,
        plaintext: &[u8],
    ) -> Result<StoredPrivateRecord, PrivateRecordError> {
        if context.key_epoch() != self.key_epoch {
            return Err(PrivateRecordError::KeyEpochMismatch);
        }
        if record_id.transaction_id() != context.transaction_id() {
            return Err(PrivateRecordError::RecordIdMismatch);
        }

        let context_bytes = context.to_bytes();
        let mut content_key = Zeroizing::new([0u8; CONTENT_KEY_BYTES]);
        let mut nonce = [0u8; NONCE_BYTES];
        rng.fill_bytes(content_key.as_mut());
        rng.fill_bytes(&mut nonce);

        let cipher = XChaCha20Poly1305::new_from_slice(content_key.as_ref())
            .map_err(|_| PrivateRecordError::RecordEncryption)?;
        let encrypted_record = cipher
            .encrypt(&XNonce::from(nonce), Payload { msg: plaintext, aad: &context_bytes })
            .map_err(|_| PrivateRecordError::RecordEncryption)?;
        let encrypted_record_key = self
            .sealing_key
            .seal_bytes_with_associated_data(rng, content_key.as_ref(), &context_bytes)
            .map_err(PrivateRecordError::ContentKeyEncryption)?;
        if encrypted_record_key.encrypted_payload.len() != CONTENT_KEY_BYTES {
            return Err(PrivateRecordError::InvalidEncryptedRecordKey);
        }

        Ok(StoredPrivateRecord {
            record_id,
            context,
            setup_context_id: self.setup_context_id,
            nonce,
            encrypted_record,
            encrypted_record_key: to_wire_bytes(&encrypted_record_key),
        })
    }
}

/// Public Golden setup used to verify shares and open private records.
#[derive(Clone, Debug)]
pub struct PrivateRecordCombiner {
    key_epoch: StorageKeyEpoch,
    setup_context_id: [u8; 32],
    combiner: Combiner<StorageGroup>,
}

impl PrivateRecordCombiner {
    /// Creates a combiner from one validated operator key without copying its secret share.
    pub fn from_operator_key(operator_key: &GoldenOperatorKey) -> Result<Self, PrivateRecordError> {
        let combiner = Combiner::new(
            operator_key.public_key_set().clone(),
            operator_key.setup_context().clone(),
        )
        .map_err(PrivateRecordError::InvalidCombinerSetup)?;
        Ok(Self {
            key_epoch: operator_key.key_epoch(),
            setup_context_id: operator_key.setup_context_id(),
            combiner,
        })
    }

    /// Verifies exact threshold share bytes and opens the private record.
    pub fn open(
        &self,
        request: &PrivateRecordShareRequest,
        record: &StoredPrivateRecord,
        share_bytes: &[Vec<u8>],
    ) -> Result<Zeroizing<Vec<u8>>, PrivateRecordError> {
        record.validate_share_request(request, self.key_epoch, self.setup_context_id)?;
        let ciphertext = record.decode_encrypted_record_key()?;
        let shares = share_bytes
            .iter()
            .map(|bytes| {
                from_wire_bytes::<DecryptionShare<StorageGroup>>(bytes)
                    .map_err(PrivateRecordError::InvalidDecryptionShare)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let context = request.context();
        let content_key = Zeroizing::new(
            self.combiner
                .combine_exact_with_associated_data(&ciphertext, context, context, &shares)
                .map_err(PrivateRecordError::ShareCombination)?,
        );
        if content_key.len() != CONTENT_KEY_BYTES {
            return Err(PrivateRecordError::InvalidEncryptedRecordKey);
        }

        let cipher = XChaCha20Poly1305::new_from_slice(content_key.as_ref())
            .map_err(|_| PrivateRecordError::RecordDecryption)?;
        cipher
            .decrypt(
                &XNonce::from(*record.nonce()),
                Payload {
                    msg: record.encrypted_record(),
                    aad: context,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| PrivateRecordError::RecordDecryption)
    }
}

#[cfg(test)]
pub(crate) fn test_private_record_sealer(
    key_epoch: StorageKeyEpoch,
    setup_context_id: [u8; 32],
) -> PrivateRecordSealer {
    use golden_core::{GoldenGroup, GoldenScalar};
    use golden_halo2curves::golden_group::Secp256k1Scalar;

    let scalar = Secp256k1Scalar::from_u64(11).expect("test scalar is valid");
    PrivateRecordSealer {
        key_epoch,
        setup_context_id,
        sealing_key: SealingKey::new(StorageGroup::mul_generator(&scalar))
            .expect("test sealing key is valid"),
    }
}

/// Database fields for one versioned private record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivateRecordStorageFields {
    /// Operational identity used to find and export the record.
    pub record_id: PrivateRecordId,
    /// Values bound into both encryption layers.
    pub context: PrivateRecordContext,
    /// Version of the context and encryption format.
    pub format_version: u32,
    /// Golden setup context identifier.
    pub setup_context_id: [u8; 32],
    /// Public record cipher nonce.
    pub nonce: Vec<u8>,
    /// Authenticated record ciphertext.
    pub encrypted_record: Vec<u8>,
    /// Canonical Golden ciphertext for the content key.
    pub encrypted_record_key: Vec<u8>,
}

/// Versioned encrypted private record stored by the validator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredPrivateRecord {
    record_id: PrivateRecordId,
    context: PrivateRecordContext,
    setup_context_id: [u8; 32],
    nonce: [u8; NONCE_BYTES],
    encrypted_record: Vec<u8>,
    encrypted_record_key: Vec<u8>,
}

impl StoredPrivateRecord {
    /// Rebuilds a record after validating its stored fields.
    pub fn from_storage_fields(
        fields: PrivateRecordStorageFields,
    ) -> Result<Self, PrivateRecordError> {
        if fields.format_version != PRIVATE_RECORD_FORMAT_V1 {
            return Err(PrivateRecordError::UnsupportedFormat(fields.format_version));
        }
        let nonce = fields.nonce.try_into().map_err(|nonce: Vec<u8>| {
            PrivateRecordError::InvalidNonceLength { actual: nonce.len() }
        })?;
        if fields.encrypted_record.len() < TAG_BYTES {
            return Err(PrivateRecordError::InvalidRecordCiphertext);
        }
        if fields.record_id.transaction_id() != fields.context.transaction_id() {
            return Err(PrivateRecordError::RecordIdMismatch);
        }

        let record = Self {
            record_id: fields.record_id,
            context: fields.context,
            setup_context_id: fields.setup_context_id,
            nonce,
            encrypted_record: fields.encrypted_record,
            encrypted_record_key: fields.encrypted_record_key,
        };
        record.verify_encrypted_record_key()?;
        Ok(record)
    }

    /// Splits a checked record into the fields stored by the database.
    pub fn into_storage_fields(self) -> PrivateRecordStorageFields {
        PrivateRecordStorageFields {
            record_id: self.record_id,
            context: self.context,
            format_version: self.context.format_version(),
            setup_context_id: self.setup_context_id,
            nonce: self.nonce.to_vec(),
            encrypted_record: self.encrypted_record,
            encrypted_record_key: self.encrypted_record_key,
        }
    }

    /// Returns the operational identity used to find and export this record.
    pub const fn record_id(&self) -> PrivateRecordId {
        self.record_id
    }

    /// Returns the values bound into both encryption layers.
    pub const fn context(&self) -> PrivateRecordContext {
        self.context
    }

    /// Returns the Golden setup context identifier.
    pub const fn setup_context_id(&self) -> &[u8; 32] {
        &self.setup_context_id
    }

    /// Returns the public record cipher nonce.
    pub const fn nonce(&self) -> &[u8; NONCE_BYTES] {
        &self.nonce
    }

    /// Returns the authenticated record ciphertext.
    pub fn encrypted_record(&self) -> &[u8] {
        &self.encrypted_record
    }

    /// Returns the canonical Golden ciphertext for the content key.
    pub fn encrypted_record_key(&self) -> &[u8] {
        &self.encrypted_record_key
    }

    /// Checks the canonical Golden content key ciphertext and its context.
    pub fn verify_encrypted_record_key(&self) -> Result<(), PrivateRecordError> {
        self.decode_encrypted_record_key().map(drop)
    }

    /// Decodes and checks the canonical Golden content key ciphertext.
    pub(crate) fn decode_encrypted_record_key(
        &self,
    ) -> Result<Ciphertext<StorageGroup>, PrivateRecordError> {
        let ciphertext: Ciphertext<StorageGroup> = from_wire_bytes(&self.encrypted_record_key)
            .map_err(PrivateRecordError::InvalidGoldenEncoding)?;
        if ciphertext.encrypted_payload.len() != CONTENT_KEY_BYTES {
            return Err(PrivateRecordError::InvalidEncryptedRecordKey);
        }
        ciphertext
            .verify_with_associated_data(&self.context.to_bytes())
            .map_err(PrivateRecordError::InvalidGoldenEncoding)?;
        Ok(ciphertext)
    }

    /// Checks that a share request, stored record, and active Golden key name the same values.
    pub(crate) fn validate_share_request(
        &self,
        request: &PrivateRecordShareRequest,
        key_epoch: StorageKeyEpoch,
        setup_context_id: [u8; 32],
    ) -> Result<(), PrivateRecordError> {
        if request.record_id() != self.record_id {
            return Err(PrivateRecordError::RecordIdMismatch);
        }
        if request.key_epoch() != self.context.key_epoch() || request.key_epoch() != key_epoch {
            return Err(PrivateRecordError::KeyEpochMismatch);
        }
        if self.setup_context_id != setup_context_id {
            return Err(PrivateRecordError::SetupContextMismatch);
        }
        if request.context() != self.context.to_bytes() {
            return Err(PrivateRecordError::DecryptionContextMismatch);
        }
        Ok(())
    }
}

impl Serializable for StoredPrivateRecord {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let context = self.context();
        target.write_bytes(PRIVATE_RECORD_BUNDLE_MAGIC);
        target.write_u32(context.format_version());
        target.write_bytes(context.chain_id().as_bytes());
        target.write_bytes(context.key_epoch().as_bytes());
        context.transaction_id().write_into(target);
        target.write_bytes(self.record_id().validator_id());
        target.write_bytes(self.setup_context_id());
        target.write_bytes(self.nonce());
        target.write_u32(
            self.encrypted_record()
                .len()
                .try_into()
                .expect("private record ciphertext exceeds the external format"),
        );
        target.write_bytes(self.encrypted_record());
        target.write_u32(
            self.encrypted_record_key()
                .len()
                .try_into()
                .expect("encrypted record key exceeds the external format"),
        );
        target.write_bytes(self.encrypted_record_key());
    }
}

impl Deserializable for StoredPrivateRecord {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        if source.read_vec(PRIVATE_RECORD_BUNDLE_MAGIC.len())? != PRIVATE_RECORD_BUNDLE_MAGIC {
            return Err(DeserializationError::InvalidValue(
                "invalid private record bundle magic".to_owned(),
            ));
        }

        let format_version = source.read_u32()?;
        let chain_id = source.read_array::<32>()?;
        let key_epoch = source.read_array::<32>()?;
        let transaction_id = TransactionId::read_from(source)?;
        let validator_id = source.read_array::<VALIDATOR_ID_BYTES>()?;
        let record_id = PrivateRecordId::from_parts(transaction_id, validator_id)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))?;
        let setup_context_id = source.read_array::<32>()?;
        let nonce = source.read_vec(NONCE_BYTES)?;
        let encrypted_record_len = source.read_u32()? as usize;
        let encrypted_record = source.read_vec(encrypted_record_len)?;
        let encrypted_record_key_len = source.read_u32()? as usize;
        let encrypted_record_key = source.read_vec(encrypted_record_key_len)?;

        Self::from_storage_fields(PrivateRecordStorageFields {
            record_id,
            context: PrivateRecordContext::new(
                PrivateRecordChainId::new(chain_id),
                StorageKeyEpoch::new(key_epoch),
                transaction_id,
            ),
            format_version,
            setup_context_id,
            nonce,
            encrypted_record,
            encrypted_record_key,
        })
        .map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

/// Error raised while sealing or reading a private record.
#[derive(Debug, thiserror::Error)]
pub enum PrivateRecordError {
    /// The record, request, and active storage key name different epochs.
    #[error("private record key epoch does not match")]
    KeyEpochMismatch,
    /// The share request names a different private record.
    #[error("private record share request names a different record")]
    RecordIdMismatch,
    /// The validator identity is not a canonical signing public key.
    #[error("private record validator id is not a canonical signing public key")]
    InvalidValidatorId(#[source] DeserializationError),
    /// The operator and record name different Golden setups.
    #[error("private record Golden setup does not match the operator")]
    SetupContextMismatch,
    /// The request does not carry the record's exact canonical context.
    #[error("private record decryption context does not match the record")]
    DecryptionContextMismatch,
    /// The decryption context bytes are not a canonical schema version 1 context.
    #[error("private record decryption context is malformed")]
    MalformedDecryptionContext,
    /// The authenticated record cipher failed.
    #[error("failed to encrypt private record")]
    RecordEncryption,
    /// Golden failed to seal the content key.
    #[error("failed to encrypt private record content key")]
    ContentKeyEncryption(#[source] golden_ehtdh1::Error),
    /// The canonical Golden value could not be decoded or verified.
    #[error("invalid Golden content key ciphertext")]
    InvalidGoldenEncoding(#[source] golden_ehtdh1::Error),
    /// The public Golden setup cannot create a combiner.
    #[error("invalid Golden combiner setup")]
    InvalidCombinerSetup(#[source] golden_ehtdh1::Error),
    /// A canonical decryption share could not be decoded.
    #[error("invalid Golden decryption share")]
    InvalidDecryptionShare(#[source] golden_ehtdh1::Error),
    /// Golden could not issue a decryption share.
    #[error("failed to issue Golden decryption share")]
    ShareGeneration(#[source] golden_ehtdh1::Error),
    /// Golden rejected the provided share set.
    #[error("failed to combine Golden decryption shares")]
    ShareCombination(#[source] golden_ehtdh1::CombineError),
    /// The Golden ciphertext does not wrap one schema version 1 content key.
    #[error("Golden ciphertext has the wrong content key size")]
    InvalidEncryptedRecordKey,
    /// The stored record format is not supported.
    #[error("unsupported private record format version {0}")]
    UnsupportedFormat(u32),
    /// The stored nonce has the wrong size.
    #[error("private record nonce has {actual} bytes, expected {NONCE_BYTES}")]
    InvalidNonceLength { actual: usize },
    /// The stored record ciphertext cannot contain an authentication tag.
    #[error("private record ciphertext is shorter than its authentication tag")]
    InvalidRecordCiphertext,
    /// The authenticated record cipher rejected the content key, context, or ciphertext.
    #[error("failed to decrypt private record")]
    RecordDecryption,
}

#[cfg(test)]
mod tests {
    use golden_ehtdh1::DecryptionShare;
    use miden_protocol::Word;
    use miden_protocol::account::auth::AuthScheme;
    use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey;
    use miden_protocol::transaction::TransactionInputs;
    use miden_protocol::utils::serde::Deserializable;
    use miden_testing::{Auth, MockChainBuilder};
    use rand_chacha_03::ChaCha20Rng;
    use rand_chacha_03::rand_core::SeedableRng;

    use super::*;
    use crate::storage_key::tests::operator_keys;

    const CHAIN_ID: PrivateRecordChainId = PrivateRecordChainId::new([1; 32]);
    const EPOCH: StorageKeyEpoch = StorageKeyEpoch::new([2; 32]);

    fn transaction_id() -> TransactionId {
        TransactionId::from_raw(Word::from([4u32, 5, 6, 7]))
    }

    fn record_id(transaction_id: TransactionId) -> PrivateRecordId {
        record_id_for_validator(transaction_id, 7)
    }

    fn record_id_for_validator(
        transaction_id: TransactionId,
        validator_seed: u8,
    ) -> PrivateRecordId {
        let signer = SigningKey::read_from_bytes(&[validator_seed; 32]).unwrap();
        PrivateRecordId::new(transaction_id, &signer.public_key())
    }

    fn context() -> PrivateRecordContext {
        PrivateRecordContext::new(CHAIN_ID, EPOCH, transaction_id())
    }

    fn sealer() -> PrivateRecordSealer {
        test_private_record_sealer(EPOCH, [8; 32])
    }

    fn threshold_record(
        operator_key: &GoldenOperatorKey,
        transaction_id: TransactionId,
        seed: u8,
        plaintext: &[u8],
    ) -> StoredPrivateRecord {
        let context = PrivateRecordContext::new(CHAIN_ID, operator_key.key_epoch(), transaction_id);
        let mut rng = ChaCha20Rng::from_seed([seed; 32]);
        PrivateRecordSealer::from_operator_key(operator_key)
            .seal(&mut rng, record_id(transaction_id), context, plaintext)
            .unwrap()
    }

    fn issue_share(
        operator_key: &GoldenOperatorKey,
        request: &PrivateRecordShareRequest,
        record: &StoredPrivateRecord,
        seed: u8,
    ) -> Vec<u8> {
        let mut rng = ChaCha20Rng::from_seed([seed; 32]);
        operator_key.issue_private_record_share(&mut rng, request, record).unwrap()
    }

    fn transaction_inputs() -> TransactionInputs {
        let mut builder = MockChainBuilder::new();
        let account = builder
            .add_existing_wallet(Auth::BasicAuth {
                auth_scheme: AuthScheme::Falcon512Poseidon2,
            })
            .unwrap();
        builder.build().unwrap().get_transaction_inputs(&account, &[], &[]).unwrap()
    }

    #[test]
    fn context_has_one_fixed_canonical_encoding() {
        let bytes = context().to_bytes();
        let transaction_id = transaction_id().to_bytes();

        assert_eq!(&bytes[..CONTEXT_DOMAIN_V1.len()], CONTEXT_DOMAIN_V1);
        assert_eq!(
            &bytes[CONTEXT_DOMAIN_V1.len()..CONTEXT_DOMAIN_V1.len() + 32],
            CHAIN_ID.as_bytes(),
        );
        assert_eq!(
            &bytes[CONTEXT_DOMAIN_V1.len() + 32..CONTEXT_DOMAIN_V1.len() + 64],
            EPOCH.as_bytes(),
        );
        assert_eq!(
            &bytes[CONTEXT_DOMAIN_V1.len() + 64..CONTEXT_DOMAIN_V1.len() + 96],
            transaction_id,
        );
        assert_eq!(&bytes[CONTEXT_DOMAIN_V1.len() + 96..], &PRIVATE_RECORD_FORMAT_V1.to_be_bytes(),);
    }

    #[test]
    fn context_parses_its_canonical_encoding_and_rejects_others() {
        let bytes = context().to_bytes();

        assert_eq!(PrivateRecordContext::try_from_bytes(&bytes).unwrap(), context());

        // Truncated, extended, wrong-domain, and wrong-version encodings are all rejected.
        let mut extended = bytes.clone();
        extended.push(0);
        let mut wrong_domain = bytes.clone();
        wrong_domain[0] ^= 1;
        let mut wrong_version = bytes.clone();
        *wrong_version.last_mut().unwrap() ^= 1;
        // A transaction id that is the right length but not canonical: an all-ones field element
        // exceeds the modulus.
        let mut wrong_transaction_id = bytes.clone();
        wrong_transaction_id[CONTEXT_DOMAIN_V1.len() + 64..CONTEXT_DOMAIN_V1.len() + 96].fill(0xff);

        let mut candidates = vec![
            bytes[..bytes.len() - 1].to_vec(),
            extended,
            wrong_domain,
            wrong_version,
            wrong_transaction_id,
        ];
        // Inputs too short for each successive field, so that every length check is exercised and
        // not just the trailing version comparison: nothing at all, then a partial domain tag,
        // chain id, key epoch, and transaction id.
        candidates.extend(
            [
                0,
                CONTEXT_DOMAIN_V1.len() - 1,
                CONTEXT_DOMAIN_V1.len() + 16,
                CONTEXT_DOMAIN_V1.len() + 48,
                CONTEXT_DOMAIN_V1.len() + 80,
            ]
            .map(|len| bytes[..len].to_vec()),
        );

        for candidate in candidates {
            assert!(
                matches!(
                    PrivateRecordContext::try_from_bytes(&candidate),
                    Err(PrivateRecordError::MalformedDecryptionContext),
                ),
                "a {}-byte context should not parse",
                candidate.len(),
            );
        }
    }

    #[test]
    fn seal_uses_a_fresh_key_and_nonce_and_wraps_only_the_key() {
        let plaintext = b"private transaction inputs";
        let mut expected_rng = ChaCha20Rng::from_seed([9; 32]);
        let mut expected_content_key = Zeroizing::new([0u8; CONTENT_KEY_BYTES]);
        let mut expected_nonce = [0u8; NONCE_BYTES];
        expected_rng.fill_bytes(expected_content_key.as_mut());
        expected_rng.fill_bytes(&mut expected_nonce);

        let mut rng = ChaCha20Rng::from_seed([9; 32]);
        let first = sealer()
            .seal(&mut rng, record_id(transaction_id()), context(), plaintext)
            .unwrap();
        let second = sealer()
            .seal(&mut rng, record_id(transaction_id()), context(), plaintext)
            .unwrap();

        assert_eq!(first.nonce(), &expected_nonce);
        assert_ne!(first.nonce(), second.nonce());
        assert_ne!(first.encrypted_record(), second.encrypted_record());
        assert_ne!(first.encrypted_record_key(), second.encrypted_record_key());
        assert_eq!(first.encrypted_record().len(), plaintext.len() + TAG_BYTES);
        assert_eq!(first.context(), context());
        assert_eq!(first.setup_context_id(), &[8; 32]);

        let cipher = XChaCha20Poly1305::new_from_slice(expected_content_key.as_ref()).unwrap();
        let opened = cipher
            .decrypt(
                &XNonce::from(*first.nonce()),
                Payload {
                    msg: first.encrypted_record(),
                    aad: &context().to_bytes(),
                },
            )
            .unwrap();
        assert_eq!(opened, plaintext);
        assert!(
            cipher
                .decrypt(
                    &XNonce::from(*first.nonce()),
                    Payload {
                        msg: first.encrypted_record(),
                        aad: b"wrong context",
                    },
                )
                .is_err(),
        );

        let encrypted_record_key = first.decode_encrypted_record_key().unwrap();
        assert_eq!(encrypted_record_key.encrypted_payload.len(), CONTENT_KEY_BYTES);
        assert_eq!(encrypted_record_key.associated_data(), context().to_bytes());
    }

    #[test]
    fn storage_fields_round_trip() {
        let mut rng = ChaCha20Rng::from_seed([12; 32]);
        let expected = sealer()
            .seal(&mut rng, record_id(transaction_id()), context(), b"record")
            .unwrap();

        let actual =
            StoredPrivateRecord::from_storage_fields(expected.clone().into_storage_fields())
                .unwrap();

        assert_eq!(actual, expected);
        assert_eq!(StoredPrivateRecord::read_from_bytes(&expected.to_bytes()).unwrap(), expected);
    }

    #[test]
    fn private_record_bundle_rejects_invalid_identity_and_magic() {
        let mut rng = ChaCha20Rng::from_seed([12; 32]);
        let record = sealer()
            .seal(&mut rng, record_id(transaction_id()), context(), b"record")
            .unwrap();
        let mut invalid_magic = record.to_bytes();
        invalid_magic[0] ^= 1;
        assert!(StoredPrivateRecord::read_from_bytes(&invalid_magic).is_err());

        let mut invalid_validator = record.to_bytes();
        let validator_offset = PRIVATE_RECORD_BUNDLE_MAGIC.len() + size_of::<u32>() + 3 * 32;
        invalid_validator[validator_offset..validator_offset + VALIDATOR_ID_BYTES].fill(0);
        assert!(StoredPrivateRecord::read_from_bytes(&invalid_validator).is_err());
    }

    #[test]
    fn storage_fields_reject_invalid_metadata() {
        let mut rng = ChaCha20Rng::from_seed([13; 32]);
        let record = sealer()
            .seal(&mut rng, record_id(transaction_id()), context(), b"record")
            .unwrap();

        let mut wrong_format = record.clone().into_storage_fields();
        wrong_format.format_version = 2;
        assert!(matches!(
            StoredPrivateRecord::from_storage_fields(wrong_format),
            Err(PrivateRecordError::UnsupportedFormat(2)),
        ));

        let mut wrong_nonce = record.clone().into_storage_fields();
        wrong_nonce.nonce.pop();
        assert!(matches!(
            StoredPrivateRecord::from_storage_fields(wrong_nonce),
            Err(PrivateRecordError::InvalidNonceLength { actual: 23 }),
        ));

        let mut short_ciphertext = record.into_storage_fields();
        short_ciphertext.encrypted_record.truncate(TAG_BYTES - 1);
        assert!(matches!(
            StoredPrivateRecord::from_storage_fields(short_ciphertext),
            Err(PrivateRecordError::InvalidRecordCiphertext),
        ));
    }

    #[test]
    fn seal_rejects_a_different_epoch() {
        let mut rng = ChaCha20Rng::from_seed([11; 32]);
        let wrong_context =
            PrivateRecordContext::new(CHAIN_ID, StorageKeyEpoch::new([99; 32]), transaction_id());

        assert!(matches!(
            sealer().seal(&mut rng, record_id(transaction_id()), wrong_context, b"record",),
            Err(PrivateRecordError::KeyEpochMismatch),
        ));
    }

    #[test]
    fn independent_writers_with_same_inputs_produce_distinct_ciphertexts() {
        let operator_keys = operator_keys();
        let transaction_id = transaction_id();
        let plaintext = transaction_inputs().to_bytes();
        let context =
            PrivateRecordContext::new(CHAIN_ID, operator_keys[0].key_epoch(), transaction_id);
        let first_record_id = record_id_for_validator(transaction_id, 7);
        let second_record_id = record_id_for_validator(transaction_id, 8);
        let mut first_rng = ChaCha20Rng::from_seed([31; 32]);
        let mut second_rng = ChaCha20Rng::from_seed([32; 32]);

        assert_eq!(operator_keys[0].sealing_key(), operator_keys[1].sealing_key());
        assert_ne!(first_record_id, second_record_id);

        let first = PrivateRecordSealer::from_operator_key(&operator_keys[0])
            .seal(&mut first_rng, first_record_id, context, &plaintext)
            .unwrap();
        let second = PrivateRecordSealer::from_operator_key(&operator_keys[1])
            .seal(&mut second_rng, second_record_id, context, &plaintext)
            .unwrap();

        assert_eq!(first.context(), second.context());
        assert_eq!(
            first.decode_encrypted_record_key().unwrap().associated_data(),
            second.decode_encrypted_record_key().unwrap().associated_data(),
        );
        assert_ne!(first.nonce(), second.nonce());
        assert_ne!(first.encrypted_record(), second.encrypted_record());
        assert_ne!(first.encrypted_record_key(), second.encrypted_record_key());
    }

    #[test]
    fn two_of_three_canonical_shares_open_the_record() {
        let operator_keys = operator_keys();
        let inputs = transaction_inputs();
        let plaintext = inputs.to_bytes();
        let record = threshold_record(&operator_keys[0], transaction_id(), 20, &plaintext);
        let request = PrivateRecordShareRequest::for_record(&record);

        let shares = [
            issue_share(&operator_keys[0], &request, &record, 22),
            issue_share(&operator_keys[1], &request, &record, 23),
        ];
        for bytes in &shares {
            let share = from_wire_bytes::<DecryptionShare<StorageGroup>>(bytes).unwrap();
            assert_eq!(to_wire_bytes(&share), *bytes);
        }

        let opened = PrivateRecordCombiner::from_operator_key(&operator_keys[2])
            .unwrap()
            .open(&request, &record, &shares)
            .unwrap();
        assert_eq!(TransactionInputs::read_from_bytes(&opened).unwrap(), inputs);
    }

    #[test]
    fn shares_for_independently_sealed_records_do_not_combine() {
        let operator_keys = operator_keys();
        let plaintext = transaction_inputs().to_bytes();
        let first_record = threshold_record(&operator_keys[0], transaction_id(), 31, &plaintext);
        let second_record = threshold_record(&operator_keys[0], transaction_id(), 32, &plaintext);
        assert_ne!(first_record.encrypted_record_key(), second_record.encrypted_record_key(),);

        let first_request = PrivateRecordShareRequest::for_record(&first_record);
        let second_request = PrivateRecordShareRequest::for_record(&second_record);
        assert_eq!(first_request, second_request);
        let shares = [
            issue_share(&operator_keys[0], &first_request, &first_record, 33),
            issue_share(&operator_keys[1], &second_request, &second_record, 34),
        ];

        let result = PrivateRecordCombiner::from_operator_key(&operator_keys[2]).unwrap().open(
            &first_request,
            &first_record,
            &shares,
        );
        assert!(matches!(result, Err(PrivateRecordError::ShareCombination(_))));
    }

    #[test]
    fn share_requests_bind_record_epoch_context_and_setup() {
        let operator_keys = operator_keys();
        let record = threshold_record(&operator_keys[0], transaction_id(), 24, b"record");
        let request = PrivateRecordShareRequest::for_record(&record);

        let wrong_transaction = PrivateRecordShareRequest::new(
            record_id(TransactionId::from_raw(Word::from([99u32; 4]))),
            request.key_epoch(),
            request.context().to_vec(),
        );
        let mut rng = ChaCha20Rng::from_seed([25; 32]);
        assert!(matches!(
            operator_keys[0].issue_private_record_share(&mut rng, &wrong_transaction, &record,),
            Err(PrivateRecordError::RecordIdMismatch),
        ));

        let wrong_epoch = PrivateRecordShareRequest::new(
            request.record_id(),
            StorageKeyEpoch::new([99; 32]),
            request.context().to_vec(),
        );
        assert!(matches!(
            operator_keys[0].issue_private_record_share(&mut rng, &wrong_epoch, &record,),
            Err(PrivateRecordError::KeyEpochMismatch),
        ));

        let mut wrong_context_bytes = request.context().to_vec();
        wrong_context_bytes[0] ^= 1;
        let wrong_context = PrivateRecordShareRequest::new(
            request.record_id(),
            request.key_epoch(),
            wrong_context_bytes,
        );
        assert!(matches!(
            operator_keys[0].issue_private_record_share(&mut rng, &wrong_context, &record,),
            Err(PrivateRecordError::DecryptionContextMismatch),
        ));

        let mut wrong_setup_fields = record.into_storage_fields();
        wrong_setup_fields.setup_context_id = [99; 32];
        let wrong_setup = StoredPrivateRecord::from_storage_fields(wrong_setup_fields).unwrap();
        assert!(matches!(
            operator_keys[0].issue_private_record_share(&mut rng, &request, &wrong_setup,),
            Err(PrivateRecordError::SetupContextMismatch),
        ));
    }

    #[test]
    fn combiner_rejects_bad_shares_and_damaged_ciphertext() {
        let operator_keys = operator_keys();
        let record = threshold_record(&operator_keys[0], transaction_id(), 26, b"record A");
        let request = PrivateRecordShareRequest::for_record(&record);
        let other_record = threshold_record(
            &operator_keys[0],
            TransactionId::from_raw(Word::from([8u32, 9, 10, 11])),
            27,
            b"record B",
        );
        let other_request = PrivateRecordShareRequest::for_record(&other_record);
        let first = issue_share(&operator_keys[0], &request, &record, 28);
        let second = issue_share(&operator_keys[1], &request, &record, 29);
        let mixed = issue_share(&operator_keys[1], &other_request, &other_record, 30);
        let combiner = PrivateRecordCombiner::from_operator_key(&operator_keys[2]).unwrap();

        assert!(matches!(
            combiner.open(&request, &record, std::slice::from_ref(&first)),
            Err(PrivateRecordError::ShareCombination(_)),
        ));
        assert!(matches!(
            combiner.open(&request, &record, &[first.clone(), first.clone()]),
            Err(PrivateRecordError::ShareCombination(_)),
        ));
        assert!(matches!(
            combiner.open(&request, &record, &[vec![0], second.clone()]),
            Err(PrivateRecordError::InvalidDecryptionShare(_)),
        ));
        assert!(matches!(
            combiner.open(&request, &record, &[first.clone(), mixed]),
            Err(PrivateRecordError::ShareCombination(_)),
        ));

        let mut damaged_fields = record.into_storage_fields();
        damaged_fields.encrypted_record[0] ^= 1;
        let damaged = StoredPrivateRecord::from_storage_fields(damaged_fields).unwrap();
        assert!(matches!(
            combiner.open(&request, &damaged, &[first, second]),
            Err(PrivateRecordError::RecordDecryption),
        ));
    }
}
