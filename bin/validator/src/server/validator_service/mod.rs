use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use miden_node_db::DatabaseError;
use miden_node_proto::domain::encryption::TransactionEncryptionKeyInfo;
use miden_protocol::Word;
use miden_protocol::block::BlockNumber;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::{PublicKey, Signature};
use miden_protocol::crypto::utils::Serializable;
use miden_protocol::errors::ProposedBlockError;
use miden_protocol::transaction::TransactionId;
use tokio::sync::{Semaphore, watch};

use crate::db::ValidatorDbWriter;
use crate::metrics::InitialMetrics;
use crate::{
    PrivateRecordChainId,
    PrivateRecordSealer,
    TransactionInputDecrypter,
    ValidatorSigner,
};

#[cfg(test)]
mod tests;

mod block_subscription;
mod block_validation;
mod get_transaction_encryption_key;
mod sign_block;
mod status;
mod submit_proven_transaction;

// VALIDATOR ERROR
// ================================================================================================

#[derive(thiserror::Error, Debug)]
pub enum ValidatorError {
    #[error("block contains unvalidated transactions {0:?}")]
    UnvalidatedTransactions(Vec<TransactionId>),
    #[error("failed to build block")]
    BlockBuildingFailed(#[source] ProposedBlockError),
    #[error("failed to sign block: {0}")]
    BlockSigningFailed(String),
    #[error("failed to select transactions")]
    DatabaseError(#[source] DatabaseError),
    #[error("block number mismatch: expected {expected}, got {actual}")]
    BlockNumberMismatch {
        expected: BlockNumber,
        actual: BlockNumber,
    },
    #[error("previous block commitment does not match chain tip")]
    PrevBlockCommitmentMismatch,
    #[error("no previous block header available for chain tip overwrite")]
    NoPrevBlockHeader,
    #[error(
        "validator signing key {actual:?} is not a member of the validator set authorized to sign this block"
    )]
    ValidatorKeyNotInSet { actual: PublicKey },
    #[error("no chain tip exists")]
    NoChainTip,
    #[error("no genesis block header exists")]
    NoGenesisHeader,
    #[error("failed to attest the transaction encryption key: {0}")]
    EncryptionKeyAttestationFailed(String),
}

/// Maps a `Result`'s error into a `tonic::Status` carrying `context` and the error's full source
/// chain, collapsing the `map_err(|err| Status::<code>(err.as_report_context(...)))` boilerplate
/// every handler repeats.
trait StatusResultExt<T> {
    /// Maps the error to [`tonic::Status::internal`].
    fn or_internal(self, context: &'static str) -> tonic::Result<T>;
    /// Maps the error to [`tonic::Status::invalid_argument`].
    fn or_invalid_argument(self, context: &'static str) -> tonic::Result<T>;
}

impl<T, E: miden_node_tracing::ErrorReport> StatusResultExt<T> for Result<T, E> {
    fn or_internal(self, context: &'static str) -> tonic::Result<T> {
        self.map_err(|err| tonic::Status::internal(err.as_report_context(context)))
    }

    fn or_invalid_argument(self, context: &'static str) -> tonic::Result<T> {
        self.map_err(|err| tonic::Status::invalid_argument(err.as_report_context(context)))
    }
}

// VALIDATOR SERVICE
// ================================================================================

/// The underlying implementation of the gRPC validator server.
///
/// Implements the gRPC API for the validator.
pub(crate) struct ValidatorService {
    signer: ValidatorSigner,
    /// Handle to the validator database. Owning the write handle makes this service the single
    /// writer; reads reach the underlying read handle through its `Deref`.
    db: ValidatorDbWriter,
    /// Decrypter for transaction inputs sealed against the shared encryption key.
    decrypter: Arc<dyn TransactionInputDecrypter>,
    /// Commitment of the genesis block, loaded once at construction.
    genesis_commitment: Word,
    /// Public Golden key used to seal private records.
    private_record_sealer: PrivateRecordSealer,
    /// Genesis commitment bound into every private record context.
    private_record_chain_id: PrivateRecordChainId,
    /// Public metadata of the shared encryption key, fetched once at construction.
    encryption_key_info: TransactionEncryptionKeyInfo,
    /// Signature by this validator's own signing key over the encryption key attestation
    /// commitment, computed once at construction.
    encryption_key_attestation: Signature,
    /// Enforces mutual exclusion between backup block subscriptions and all other RPCs. Regular
    /// RPCs take the read side (any number may run concurrently); a backup subscription takes the
    /// exclusive write side for its entire lifetime. Acquired with `try_*` on both sides so that a
    /// conflicting request fails fast with `resource_exhausted` rather than blocking.
    serve_lock: Arc<tokio::sync::RwLock<()>>,
    /// Serializes `sign_block` requests so that concurrent calls are processed sequentially,
    /// ensuring consistent chain tip reads and preventing race conditions.
    sign_block_semaphore: Semaphore,
    /// Bounds concurrently executing transaction validations. Proof verification and re-execution
    /// each pin a CPU on the blocking pool, and unbounded concurrency saturates every core,
    /// starving the async runtime — and with it `sign_block` — of CPU time. A delayed block
    /// signature stalls the whole chain. A delayed validation only slows transaction admission: the
    /// RPC submits every transaction to every validator before it may enter the mempool, so blocks
    /// are proposed exclusively from already-validated transactions and signing never waits on
    /// validation. Validation is therefore capped below the core count to keep signing headroom.
    tx_validation_semaphore: Semaphore,
    /// In-memory chain tip, updated after each signed block. Block subscriptions follow this to
    /// stream live blocks as they are signed.
    committed_tip: watch::Sender<BlockNumber>,
    /// In-memory count of validated transactions, incremented after each new insert.
    validated_transactions_count: AtomicU64,
    /// In-memory count of signed blocks, incremented after each signed block that extends the
    /// chain. A replacement of the tip block does not change it.
    signed_blocks_count: AtomicU64,
}

impl ValidatorService {
    pub(crate) async fn new(
        signer: ValidatorSigner,
        db: ValidatorDbWriter,
        decrypter: Arc<dyn TransactionInputDecrypter>,
        private_record_sealer: PrivateRecordSealer,
        initial_metrics: InitialMetrics,
    ) -> Result<Self, ValidatorError> {
        // The chain tip's header commits to the validator set authorized to sign the next block, so
        // the signing key must be a member of that set for this validator to be useful. Reject a
        // misconfigured key here.
        let chain_tip = db
            .load_chain_tip()
            .await
            .map_err(ValidatorError::DatabaseError)?
            .ok_or(ValidatorError::NoChainTip)?;
        let signing_key = signer.public_key();
        if !chain_tip.validator_config().keys().contains(&signing_key) {
            return Err(ValidatorError::ValidatorKeyNotInSet { actual: signing_key });
        }

        // Both keys are fixed for the process lifetime, so the attestation is computed once. This
        // also keeps KMS-backed signers to a single signing call.
        let genesis_commitment = db
            .load_block_header(BlockNumber::GENESIS)
            .await
            .map_err(ValidatorError::DatabaseError)?
            .ok_or(ValidatorError::NoGenesisHeader)?
            .commitment();
        let private_record_chain_id = PrivateRecordChainId::new(
            genesis_commitment
                .to_bytes()
                .try_into()
                .expect("a Miden block commitment is always 32 bytes"),
        );
        let encryption_key_info = decrypter
            .encryption_key()
            .await
            .map_err(|err| ValidatorError::EncryptionKeyAttestationFailed(err.to_string()))?;
        let encryption_key_attestation = signer
            .sign_commitment(encryption_key_info.attestation_commitment(genesis_commitment))
            .await
            .map_err(|err| ValidatorError::EncryptionKeyAttestationFailed(err.to_string()))?;
        Ok(Self {
            signer,
            decrypter,
            genesis_commitment,
            private_record_sealer,
            private_record_chain_id,
            encryption_key_info,
            encryption_key_attestation,
            serve_lock: Arc::new(tokio::sync::RwLock::new(())),
            db,
            sign_block_semaphore: Semaphore::new(1),
            tx_validation_semaphore: Semaphore::new(max_tx_concurrency()),
            committed_tip: watch::Sender::new(BlockNumber::from(initial_metrics.chain_tip)),
            validated_transactions_count: AtomicU64::new(initial_metrics.validated_transactions),
            signed_blocks_count: AtomicU64::new(initial_metrics.signed_blocks),
        })
    }
}

/// Number of transaction validations allowed to execute concurrently: the core count minus headroom
/// reserved for the async runtime and the block-signing path, at least one.
fn max_tx_concurrency() -> usize {
    std::thread::available_parallelism().map_or(1, |n| n.get().saturating_sub(2).max(1))
}
