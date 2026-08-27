use std::fmt;

use golden_core::{GoldenGroup, ParticipantIndex};
use golden_ehtdh1::wire::{from_wire_bytes, to_wire_bytes};
use golden_ehtdh1::{
    Ciphertext,
    PublicKeySet,
    SealingKey,
    SecretShare,
    SetupContext,
    UnsealingShare,
    derive_context_session_id,
};
use golden_halo2curves::golden_group::Secp256k1GoldenGroup;
use miden_protocol::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use rand_core_06::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::private_record::CONTENT_KEY_BYTES;
use crate::{PrivateRecordError, PrivateRecordShareRequest, StoredPrivateRecord};

/// Golden group used for validator storage keys.
type StorageGroup = Secp256k1GoldenGroup;

/// Identifier for one version of the validator storage key.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct StorageKeyEpoch([u8; 32]);

impl StorageKeyEpoch {
    /// Creates a storage key epoch from its canonical bytes.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Parses a storage key epoch from its hex encoding.
    pub fn from_hex(encoded: impl AsRef<[u8]>) -> Result<Self, hex::FromHexError> {
        let mut bytes = [0; 32];
        hex::decode_to_slice(encoded, &mut bytes)?;
        Ok(Self(bytes))
    }

    /// Returns the canonical epoch bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Serializable for StorageKeyEpoch {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(&self.0);
    }
}

impl Deserializable for StorageKeyEpoch {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self(source.read_array()?))
    }
}

/// Canonical Golden values needed to restore one validator operator key.
pub struct EncodedGoldenOperatorKey {
    key_epoch: StorageKeyEpoch,
    setup_context: Vec<u8>,
    public_key_set: Vec<u8>,
    secret_share: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for EncodedGoldenOperatorKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncodedGoldenOperatorKey")
            .field("key_epoch", &self.key_epoch)
            .field("setup_context_bytes", &self.setup_context.len())
            .field("public_key_set_bytes", &self.public_key_set.len())
            .field("secret_share", &"<redacted>")
            .finish()
    }
}

impl EncodedGoldenOperatorKey {
    /// Creates a restart bundle from canonical Golden wire values.
    pub fn new(
        key_epoch: StorageKeyEpoch,
        setup_context: Vec<u8>,
        public_key_set: Vec<u8>,
        secret_share: Vec<u8>,
    ) -> Self {
        Self {
            key_epoch,
            setup_context,
            public_key_set,
            secret_share: Zeroizing::new(secret_share),
        }
    }

    /// Splits the bundle into its epoch, setup, public key set, and protected secret share.
    pub fn into_parts(self) -> (StorageKeyEpoch, Vec<u8>, Vec<u8>, Zeroizing<Vec<u8>>) {
        (self.key_epoch, self.setup_context, self.public_key_set, self.secret_share)
    }

    /// Decodes and validates the operator key.
    pub fn decode(self) -> Result<GoldenOperatorKey, GoldenOperatorKeyError> {
        let setup_context = from_wire_bytes(&self.setup_context).map_err(|source| {
            GoldenOperatorKeyError::InvalidWireValue { field: "setup context", source }
        })?;
        let public_key_set = from_wire_bytes(&self.public_key_set).map_err(|source| {
            GoldenOperatorKeyError::InvalidWireValue { field: "public key set", source }
        })?;
        let secret_share = from_wire_bytes(&self.secret_share).map_err(|source| {
            GoldenOperatorKeyError::InvalidWireValue { field: "secret share", source }
        })?;

        GoldenOperatorKey::new(self.key_epoch, setup_context, public_key_set, secret_share)
    }
}

/// Validated Golden material held by one validator operator.
pub struct GoldenOperatorKey {
    key_epoch: StorageKeyEpoch,
    setup_context: SetupContext,
    public_key_set: PublicKeySet<StorageGroup>,
    secret_share: SecretShare<StorageGroup>,
    sealing_key: SealingKey<StorageGroup>,
}

impl fmt::Debug for GoldenOperatorKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GoldenOperatorKey")
            .field("key_epoch", &self.key_epoch)
            .field("setup_context", &self.setup_context)
            .field("public_key_set", &self.public_key_set)
            .field("secret_share", &"<redacted>")
            .field("sealing_key", &self.sealing_key)
            .finish()
    }
}

impl GoldenOperatorKey {
    /// Creates an operator key after checking its public and private material.
    pub fn new(
        key_epoch: StorageKeyEpoch,
        setup_context: SetupContext,
        public_key_set: PublicKeySet<StorageGroup>,
        secret_share: SecretShare<StorageGroup>,
    ) -> Result<Self, GoldenOperatorKeyError> {
        if setup_context.backend_id != StorageGroup::BACKEND_ID {
            return Err(GoldenOperatorKeyError::BackendMismatch {
                expected: StorageGroup::BACKEND_ID,
                actual: setup_context.backend_id,
            });
        }
        if setup_context.context_session_id
            != derive_context_session_id(setup_context.decryption_session_id)
        {
            return Err(GoldenOperatorKeyError::ContextSessionMismatch);
        }

        let public_key_set = PublicKeySet::new(
            public_key_set.threshold,
            public_key_set.joint_public_key,
            public_key_set.public_shares,
        )
        .map_err(GoldenOperatorKeyError::InvalidPublicKeySet)?;

        if setup_context.threshold != public_key_set.threshold {
            return Err(GoldenOperatorKeyError::ThresholdMismatch {
                setup: setup_context.threshold,
                public_key_set: public_key_set.threshold,
            });
        }

        let participants =
            public_key_set.public_shares.keys().copied().collect::<Vec<ParticipantIndex>>();
        if setup_context.participants != participants {
            return Err(GoldenOperatorKeyError::ParticipantSetMismatch);
        }

        let public_share = public_key_set.public_share(secret_share.participant).ok_or(
            GoldenOperatorKeyError::UnknownLocalParticipant(secret_share.participant.get()),
        )?;
        if public_share.decryption != StorageGroup::mul_generator(&secret_share.decryption)
            || public_share.context != StorageGroup::mul_generator(&secret_share.context)
        {
            return Err(GoldenOperatorKeyError::SecretShareMismatch);
        }
        if setup_context.epoch != *key_epoch.as_bytes() {
            return Err(GoldenOperatorKeyError::EpochMismatch);
        }

        let sealing_key = SealingKey::new(public_key_set.joint_public_key)
            .map_err(GoldenOperatorKeyError::InvalidSealingKey)?;

        Ok(Self {
            key_epoch,
            setup_context,
            public_key_set,
            secret_share,
            sealing_key,
        })
    }

    /// Returns canonical values that can restore this operator key.
    pub fn encode(&self) -> EncodedGoldenOperatorKey {
        EncodedGoldenOperatorKey::new(
            self.key_epoch,
            to_wire_bytes(&self.setup_context),
            to_wire_bytes(&self.public_key_set),
            to_wire_bytes(&self.secret_share),
        )
    }

    /// Returns the storage key epoch.
    pub const fn key_epoch(&self) -> StorageKeyEpoch {
        self.key_epoch
    }

    /// Returns the setup context identifier.
    pub fn setup_context_id(&self) -> [u8; 32] {
        self.setup_context.root()
    }

    /// Returns the public sealing key for this epoch.
    pub const fn sealing_key(&self) -> &SealingKey<StorageGroup> {
        &self.sealing_key
    }

    /// Returns the public key set used to verify decryption shares.
    pub const fn public_key_set(&self) -> &PublicKeySet<StorageGroup> {
        &self.public_key_set
    }

    /// Returns the Golden setup context.
    pub const fn setup_context(&self) -> &SetupContext {
        &self.setup_context
    }

    /// Returns the participant that owns this operator key.
    pub const fn participant(&self) -> ParticipantIndex {
        self.secret_share.participant
    }

    /// Issues a canonical decryption share for one encrypted content key and exact context.
    pub(crate) fn issue_decryption_share<R>(
        &self,
        rng: &mut R,
        ciphertext_bytes: &[u8],
        context: &[u8],
    ) -> Result<Vec<u8>, PrivateRecordError>
    where
        R: RngCore + CryptoRng,
    {
        let ciphertext: Ciphertext<StorageGroup> =
            from_wire_bytes(ciphertext_bytes).map_err(PrivateRecordError::InvalidGoldenEncoding)?;
        if ciphertext.encrypted_payload.len() != CONTENT_KEY_BYTES {
            return Err(PrivateRecordError::InvalidEncryptedRecordKey);
        }
        ciphertext
            .verify_with_associated_data(context)
            .map_err(PrivateRecordError::InvalidGoldenEncoding)?;

        let share = UnsealingShare::new(self.secret_share.clone())
            .decrypt_share_with_associated_data(
                rng,
                &self.setup_context,
                &ciphertext,
                context,
                context,
            )
            .map_err(PrivateRecordError::ShareGeneration)?;
        Ok(to_wire_bytes(&share))
    }

    /// Checks one private-record request and returns a canonical decryption share.
    pub fn issue_private_record_share<R>(
        &self,
        rng: &mut R,
        request: &PrivateRecordShareRequest,
        record: &StoredPrivateRecord,
    ) -> Result<Vec<u8>, PrivateRecordError>
    where
        R: RngCore + CryptoRng,
    {
        record.validate_share_request(request, self.key_epoch, self.setup_context_id())?;
        self.issue_decryption_share(rng, record.encrypted_record_key(), request.context())
    }
}

/// Error raised while loading a Golden operator key.
#[derive(Debug, thiserror::Error)]
pub enum GoldenOperatorKeyError {
    /// A canonical Golden value could not be decoded.
    #[error("invalid Golden {field}")]
    InvalidWireValue {
        field: &'static str,
        #[source]
        source: golden_ehtdh1::Error,
    },
    /// The setup names a different group backend.
    #[error("Golden backend mismatch: expected {expected}, got {actual}")]
    BackendMismatch { expected: &'static str, actual: String },
    /// The context session was not derived from the decryption session.
    #[error("Golden context session does not match the decryption session")]
    ContextSessionMismatch,
    /// The public key set is not internally valid.
    #[error("invalid Golden public key set")]
    InvalidPublicKeySet(#[source] golden_ehtdh1::Error),
    /// The threshold differs between public setup values.
    #[error(
        "Golden threshold mismatch: setup context uses {setup}, public key set uses {public_key_set}"
    )]
    ThresholdMismatch { setup: usize, public_key_set: usize },
    /// The participant list differs between public setup values.
    #[error("Golden participant set mismatch")]
    ParticipantSetMismatch,
    /// The local secret share has no matching public share.
    #[error("Golden participant {0} is not in the public key set")]
    UnknownLocalParticipant(u32),
    /// The local secret share does not open its public points.
    #[error("Golden secret share does not match its public share")]
    SecretShareMismatch,
    /// The node epoch differs from the Golden setup epoch.
    #[error("Golden setup epoch does not match the node storage key epoch")]
    EpochMismatch,
    /// The joint public key cannot be used for sealing.
    #[error("invalid Golden sealing key")]
    InvalidSealingKey(#[source] golden_ehtdh1::Error),
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::BTreeMap;

    use golden_core::{GoldenScalar, SessionId};
    use golden_ehtdh1::{PublicShare, derive_context_session_id};
    use golden_halo2curves::golden_group::Secp256k1Scalar;

    use super::*;

    const EPOCH: StorageKeyEpoch = StorageKeyEpoch::new([9; 32]);

    fn participant(value: u32) -> ParticipantIndex {
        ParticipantIndex::new(value).unwrap()
    }

    fn scalar(value: u64) -> Secp256k1Scalar {
        Secp256k1Scalar::from_u64(value).unwrap()
    }

    fn evaluate(
        secret: Secp256k1Scalar,
        coefficient: Secp256k1Scalar,
        participant: ParticipantIndex,
    ) -> Secp256k1Scalar {
        secret.add(&coefficient.mul(&participant.to_scalar().unwrap()))
    }

    fn values_for(
        local_participant: ParticipantIndex,
    ) -> (SetupContext, PublicKeySet<StorageGroup>, SecretShare<StorageGroup>) {
        let participants = [participant(1), participant(2), participant(3)];
        let decryption_secret = scalar(11);
        let decryption_coefficient = scalar(7);
        let context_coefficient = scalar(13);
        let mut public_shares = BTreeMap::new();
        let mut local_secret_share = None;

        for participant in participants {
            let decryption = evaluate(decryption_secret, decryption_coefficient, participant);
            let context = evaluate(scalar(0), context_coefficient, participant);
            public_shares.insert(
                participant,
                PublicShare {
                    decryption: StorageGroup::mul_generator(&decryption),
                    context: StorageGroup::mul_generator(&context),
                },
            );
            if participant == local_participant {
                local_secret_share = Some(SecretShare { participant, decryption, context });
            }
        }

        let decryption_session_id = SessionId([2; 32]);
        let setup_context = SetupContext {
            backend_id: StorageGroup::BACKEND_ID.to_owned(),
            threshold: 2,
            registry_root: [1; 32],
            participants: participants.to_vec(),
            decryption_session_id,
            context_session_id: derive_context_session_id(decryption_session_id),
            decryption_transcript_root: [3; 32],
            context_transcript_root: [4; 32],
            epoch: *EPOCH.as_bytes(),
        };
        let public_key_set =
            PublicKeySet::new(2, StorageGroup::mul_generator(&decryption_secret), public_shares)
                .unwrap();

        (setup_context, public_key_set, local_secret_share.unwrap())
    }

    fn values() -> (SetupContext, PublicKeySet<StorageGroup>, SecretShare<StorageGroup>) {
        values_for(participant(1))
    }

    pub(crate) fn operator_keys() -> Vec<GoldenOperatorKey> {
        [participant(1), participant(2), participant(3)]
            .into_iter()
            .map(|participant| {
                let (setup_context, public_key_set, secret_share) = values_for(participant);
                GoldenOperatorKey::new(EPOCH, setup_context, public_key_set, secret_share).unwrap()
            })
            .collect()
    }

    fn operator_key() -> GoldenOperatorKey {
        operator_keys().remove(0)
    }

    /// Regenerates the committed insecure storage-key fixture under
    /// `scripts/testdata/insecure-storage-key/`.
    ///
    /// The fixture holds a full two-of-three setup: one shared
    /// `setup-context.wire` and `public-key-set.wire`, plus a *distinct*
    /// `validator-<n>/secret-share.wire` for each participant. This lets the
    /// docker-compose network give every validator its own share, which is
    /// required for a real threshold recovery — mounting the same share into
    /// all three validators makes any 2-of-3 combine collapse to a single
    /// participant and fail.
    ///
    /// Ignored by default so it never runs in CI; regenerate the fixture with:
    ///
    /// ```text
    /// cargo test -p miden-validator --lib storage_key::tests::write_insecure_storage_key_fixture -- --ignored
    /// ```
    #[test]
    #[ignore = "writes fixture files; run explicitly to regenerate"]
    fn write_insecure_storage_key_fixture() {
        use std::path::Path;

        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/testdata/insecure-storage-key");
        fs_err::create_dir_all(&dir).unwrap();

        let (setup_context, public_key_set, _) = values_for(participant(1));
        fs_err::write(dir.join("setup-context.wire"), to_wire_bytes(&setup_context)).unwrap();
        fs_err::write(dir.join("public-key-set.wire"), to_wire_bytes(&public_key_set)).unwrap();

        for index in [1u32, 2, 3] {
            let (.., secret_share) = values_for(participant(index));
            let validator_dir = dir.join(format!("validator-{index}"));
            fs_err::create_dir_all(&validator_dir).unwrap();
            fs_err::write(validator_dir.join("secret-share.wire"), to_wire_bytes(&secret_share))
                .unwrap();
        }
    }

    #[test]
    fn restart_bundle_round_trips() {
        let expected = operator_key();
        let decoded = expected.encode().decode().unwrap();

        assert_eq!(decoded.key_epoch(), EPOCH);
        assert_eq!(decoded.setup_context(), expected.setup_context());
        assert_eq!(decoded.public_key_set(), expected.public_key_set());
        assert_eq!(decoded.participant(), expected.participant());
        assert_eq!(decoded.sealing_key(), expected.sealing_key());
        assert_eq!(decoded.setup_context_id(), expected.setup_context_id());
    }

    #[test]
    fn restart_bundle_exposes_persisted_parts() {
        let expected = operator_key();
        let (key_epoch, setup_context, public_key_set, secret_share) =
            expected.encode().into_parts();
        let decoded_setup = from_wire_bytes::<SetupContext>(&setup_context).unwrap();
        let decoded_public_key_set =
            from_wire_bytes::<PublicKeySet<StorageGroup>>(&public_key_set).unwrap();

        assert_eq!(key_epoch, EPOCH);
        assert_eq!(&decoded_setup, expected.setup_context());
        assert_eq!(&decoded_public_key_set, expected.public_key_set());
        assert!(from_wire_bytes::<SecretShare<StorageGroup>>(&secret_share).is_ok());
    }

    #[test]
    fn rejects_inconsistent_public_setup() {
        let (mut setup_context, public_key_set, secret_share) = values();
        setup_context.backend_id = "wrong-backend".to_owned();
        assert!(matches!(
            GoldenOperatorKey::new(EPOCH, setup_context, public_key_set, secret_share),
            Err(GoldenOperatorKeyError::BackendMismatch { .. })
        ));

        let (mut setup_context, public_key_set, secret_share) = values();
        setup_context.context_session_id = SessionId([8; 32]);
        assert!(matches!(
            GoldenOperatorKey::new(EPOCH, setup_context, public_key_set, secret_share),
            Err(GoldenOperatorKeyError::ContextSessionMismatch)
        ));

        let (mut setup_context, public_key_set, secret_share) = values();
        setup_context.threshold = 3;
        assert!(matches!(
            GoldenOperatorKey::new(EPOCH, setup_context, public_key_set, secret_share),
            Err(GoldenOperatorKeyError::ThresholdMismatch { .. })
        ));

        let (mut setup_context, public_key_set, secret_share) = values();
        setup_context.participants.pop();
        assert!(matches!(
            GoldenOperatorKey::new(EPOCH, setup_context, public_key_set, secret_share),
            Err(GoldenOperatorKeyError::ParticipantSetMismatch)
        ));
    }

    #[test]
    fn rejects_invalid_local_secret() {
        let (setup_context, public_key_set, mut secret_share) = values();
        secret_share.participant = participant(4);
        assert!(matches!(
            GoldenOperatorKey::new(EPOCH, setup_context, public_key_set, secret_share),
            Err(GoldenOperatorKeyError::UnknownLocalParticipant(4))
        ));

        let (setup_context, public_key_set, mut secret_share) = values();
        secret_share.decryption = secret_share.decryption.add(&scalar(1));
        assert!(matches!(
            GoldenOperatorKey::new(EPOCH, setup_context, public_key_set, secret_share),
            Err(GoldenOperatorKeyError::SecretShareMismatch)
        ));
    }

    #[test]
    fn rejects_epoch_mismatch() {
        let (setup_context, public_key_set, secret_share) = values();
        assert!(matches!(
            GoldenOperatorKey::new(
                StorageKeyEpoch::new([10; 32]),
                setup_context,
                public_key_set,
                secret_share,
            ),
            Err(GoldenOperatorKeyError::EpochMismatch)
        ));
    }

    #[test]
    fn rejects_malformed_restart_value() {
        let mut encoded = operator_key().encode();
        encoded.setup_context.pop();

        assert!(matches!(
            encoded.decode(),
            Err(GoldenOperatorKeyError::InvalidWireValue { field: "setup context", .. })
        ));
    }
}
