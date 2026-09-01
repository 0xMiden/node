use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use miden_node_db::DatabaseError;
use miden_node_proto::domain::encryption::TransactionEncryptionKeyInfo;
use miden_node_store::BlockStore;
use miden_node_tracing::spawn::spawn_blocking_in_current_span;
use miden_node_tracing::{miden_instrument, miden_span_record};
use miden_protocol::Word;
use miden_protocol::block::{
    BlockHeader,
    BlockNumber,
    BlockSignatures,
    ProposedBlock,
    SignedBlock,
};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::{PublicKey, Signature};
use miden_protocol::crypto::utils::Serializable;
use miden_protocol::errors::ProposedBlockError;
use miden_protocol::transaction::{TransactionHeader, TransactionId};
use tokio::sync::{Semaphore, watch};

use crate::db::ValidatorDbWriter;
use crate::metrics::InitialMetrics;
use crate::{
    COMPONENT,
    PrivateRecordChainId,
    PrivateRecordSealer,
    TransactionInputDecrypter,
    ValidatorSigner,
};

#[cfg(test)]
mod tests;

mod block_subscription;
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
    #[error("failed to backup block")]
    BlockBackupFailed(#[source] std::io::Error),
    #[error("no genesis block header exists")]
    NoGenesisHeader,
    #[error("failed to attest the transaction encryption key: {0}")]
    EncryptionKeyAttestationFailed(String),
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
    block_store: BlockStore,
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
    /// In-memory count of signed blocks, incremented after each signed block.
    signed_blocks_count: AtomicU64,
}

impl ValidatorService {
    pub(crate) async fn new(
        signer: ValidatorSigner,
        db: ValidatorDbWriter,
        decrypter: Arc<dyn TransactionInputDecrypter>,
        private_record_sealer: PrivateRecordSealer,
        block_store: BlockStore,
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
            block_store,
            sign_block_semaphore: Semaphore::new(1),
            tx_validation_semaphore: Semaphore::new(max_tx_concurrency()),
            committed_tip: watch::Sender::new(BlockNumber::from(initial_metrics.chain_tip)),
            validated_transactions_count: AtomicU64::new(initial_metrics.validated_transactions),
            signed_blocks_count: AtomicU64::new(initial_metrics.signed_blocks),
        })
    }

    /// Validates a proposed block by checking:
    /// 1. All transactions have been previously validated by this validator.
    /// 2. The block header can be successfully built from the proposed block.
    /// 3. The block is either: a. The valid next block in the chain (sequential block number, matching
    ///    previous block commitment), or b. A replacement block at the same height as the current chain
    ///    tip, validated against the previous block header.
    ///
    /// On success, returns the signed block carrying this validator's signature.
    #[miden_instrument(
        target = COMPONENT,
        err,
    )]
    pub async fn validate_block(
        &self,
        proposed_block: ProposedBlock,
        chain_tip: BlockHeader,
    ) -> Result<SignedBlock, ValidatorError> {
        miden_span_record!(tip.number = chain_tip.block_num());

        // Search for any proposed transactions that have not previously been validated.
        let proposed_tx_ids =
            proposed_block.transactions().map(TransactionHeader::id).collect::<Vec<_>>();
        let unvalidated_txs = self
            .db
            .find_unvalidated_transactions(proposed_tx_ids)
            .await
            .map_err(ValidatorError::DatabaseError)?;

        // All proposed transactions must have been validated.
        if !unvalidated_txs.is_empty() {
            return Err(ValidatorError::UnvalidatedTransactions(unvalidated_txs));
        }
        // Build the block header. This computes the account, nullifier and note tree roots plus the
        // chain and transaction commitments — hashing proportional to block contents — so it runs
        // on a blocking thread rather than pinning an async worker.
        let (proposed_header, proposed_body) =
            spawn_blocking_in_current_span(move || proposed_block.into_header_and_body())
                .await
                .unwrap_or_else(|e| std::panic::resume_unwind(e.into_panic()))
                .map_err(ValidatorError::BlockBuildingFailed)?;

        miden_span_record!(
            block.number = proposed_header.block_num(),
            block.commitment = proposed_header.commitment()
        );

        // If the proposed block has the same block number as the current chain tip, this is a
        // replacement block. Validate it against the previous block header.
        let prev = if proposed_header.block_num() == chain_tip.block_num() {
            // The genesis block cannot be replaced (genesis block has no parent).
            let prev_block_num =
                chain_tip.block_num().parent().ok_or(ValidatorError::NoPrevBlockHeader)?;
            self.db
                .load_block_header(prev_block_num)
                .await
                .map_err(ValidatorError::DatabaseError)?
                .ok_or(ValidatorError::NoPrevBlockHeader)?
        } else {
            // Proposed block is a new block. Block number must be sequential.
            let expected_block_num = chain_tip.block_num().child();
            if proposed_header.block_num() != expected_block_num {
                return Err(ValidatorError::BlockNumberMismatch {
                    expected: expected_block_num,
                    actual: proposed_header.block_num(),
                });
            }
            // Current chain tip is the parent of the proposed block.
            chain_tip
        };

        // The proposed block's parent must match the block that the Validator has determined is its
        // parent (either chain tip or parent of chain tip).
        if proposed_header.prev_block_commitment() != prev.commitment() {
            return Err(ValidatorError::PrevBlockCommitmentMismatch);
        }

        // Check that our key is a member of the validator set authorized to sign this block,
        // which is the set committed to by the parent's header.
        //
        // Otherwise we would be producing a signature that cannot be placed in the block's
        // signature set.
        let signing_key = self.signer.public_key();
        if !prev.validator_config().keys().contains(&signing_key) {
            return Err(ValidatorError::ValidatorKeyNotInSet { actual: signing_key });
        }

        let signature = self.sign_header(&proposed_header).await?;

        // Back up the signed block to disk.
        //
        // Note that the backup only carries this validator's own signature: the complete,
        // positionally ordered signature set exists only at the block producer once it has
        // aggregated the responses of all validators. Consumers of the backup stream must not
        // expect to verify the full signature set from these blocks.
        let own_signature = BlockSignatures::new(vec![signature.clone()])
            .expect("a single signature is within the signature set bounds");
        let signed_block =
            SignedBlock::new_unchecked(proposed_header, proposed_body, own_signature);
        // Serializing the full block also scales with its contents; run it on a blocking thread.
        let (signed_block, signed_block_bytes) = spawn_blocking_in_current_span(move || {
            let bytes = signed_block.to_bytes();
            (signed_block, bytes)
        })
        .await
        .unwrap_or_else(|e| std::panic::resume_unwind(e.into_panic()));
        self.block_store
            .save_block(signed_block.header().block_num(), &signed_block_bytes)
            .await
            .map_err(ValidatorError::BlockBackupFailed)?;

        Ok(signed_block)
    }

    /// Signs a block header using the validator's signer.
    #[miden_instrument(
        target = COMPONENT,
        name = "sign_block",
        err,
        fields(
            block.number = header.block_num(),
        ),
    )]
    async fn sign_header(&self, header: &BlockHeader) -> Result<Signature, ValidatorError> {
        self.signer
            .sign_commitment(header.commitment())
            .await
            .map_err(|err| ValidatorError::BlockSigningFailed(err.to_string()))
    }
}

/// Number of transaction validations allowed to execute concurrently: the core count minus headroom
/// reserved for the async runtime and the block-signing path, at least one.
fn max_tx_concurrency() -> usize {
    std::thread::available_parallelism().map_or(1, |n| n.get().saturating_sub(2).max(1))
}
