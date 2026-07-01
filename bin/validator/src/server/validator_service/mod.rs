use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use miden_node_db::{DatabaseError, Db};
use miden_node_store::BlockStore;
use miden_node_utils::tracing::{miden_instrument, miden_span_record};
use miden_protocol::block::{BlockHeader, BlockNumber, ProposedBlock, SignedBlock};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::{PublicKey, Signature};
use miden_protocol::crypto::utils::Serializable;
use miden_protocol::errors::ProposedBlockError;
use miden_protocol::transaction::{TransactionHeader, TransactionId};
use tokio::sync::{Semaphore, watch};

use crate::db::{find_unvalidated_transactions, load_block_header, load_chain_tip};
use crate::{COMPONENT, ValidatorSigner};

#[cfg(test)]
mod tests;

mod block_subscription;
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
        "validator signing key {actual:?} does not match the block's validator key {expected:?}"
    )]
    ValidatorKeyMismatch { expected: PublicKey, actual: PublicKey },
    #[error("no chain tip exists")]
    NoChainTip,
    #[error("failed to backup block")]
    BlockBackupFailed(#[source] std::io::Error),
}

// VALIDATOR SERVICE
// ================================================================================

/// The underlying implementation of the gRPC validator server.
///
/// Implements the gRPC API for the validator.
pub(crate) struct ValidatorService {
    signer: ValidatorSigner,
    db: Arc<Db>,
    block_store: BlockStore,
    /// Enforces mutual exclusion between backup block subscriptions and all other RPCs. Regular
    /// RPCs take the read side (any number may run concurrently); a backup subscription takes the
    /// exclusive write side for its entire lifetime. Acquired with `try_*` on both sides so that a
    /// conflicting request fails fast with `resource_exhausted` rather than blocking.
    serve_lock: Arc<tokio::sync::RwLock<()>>,
    /// Serializes `sign_block` requests so that concurrent calls are processed sequentially,
    /// ensuring consistent chain tip reads and preventing race conditions.
    sign_block_semaphore: Semaphore,
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
        db: Db,
        block_store: BlockStore,
        initial_chain_tip: u32,
        initial_tx_count: u64,
        initial_block_count: u64,
    ) -> Result<Self, ValidatorError> {
        // The validator key is fixed at genesis and carried forward unchanged by every block, so
        // the signing key must match the chain's validator key for this validator's lifetime.
        // Reject a misconfigured key here.
        let chain_tip = db
            .query("load_chain_tip", load_chain_tip)
            .await
            .map_err(ValidatorError::DatabaseError)?
            .ok_or(ValidatorError::NoChainTip)?;
        let signing_key = signer.public_key();
        if &signing_key != chain_tip.validator_key() {
            return Err(ValidatorError::ValidatorKeyMismatch {
                expected: chain_tip.validator_key().clone(),
                actual: signing_key,
            });
        }

        Ok(Self {
            signer,
            serve_lock: Arc::new(tokio::sync::RwLock::new(())),
            db: db.into(),
            block_store,
            sign_block_semaphore: Semaphore::new(1),
            committed_tip: watch::Sender::new(BlockNumber::from(initial_chain_tip)),
            validated_transactions_count: AtomicU64::new(initial_tx_count),
            signed_blocks_count: AtomicU64::new(initial_block_count),
        })
    }

    /// Validates a proposed block by checking:
    /// 1. All transactions have been previously validated by this validator.
    /// 2. The block header can be successfully built from the proposed block.
    /// 3. The block is either: a. The valid next block in the chain (sequential block number, matching
    ///    previous block commitment), or b. A replacement block at the same height as the current chain
    ///    tip, validated against the previous block header.
    ///
    /// On success, returns the signature and the validated block header.
    #[miden_instrument(
        target = COMPONENT,
        skip_all,
        err,
    )]
    pub async fn validate_block(
        &self,
        proposed_block: ProposedBlock,
        chain_tip: BlockHeader,
    ) -> Result<(Signature, BlockHeader), ValidatorError> {
        miden_span_record!(tip.number = chain_tip.block_num().as_u32(),);

        // Search for any proposed transactions that have not previously been validated.
        let proposed_tx_ids =
            proposed_block.transactions().map(TransactionHeader::id).collect::<Vec<_>>();
        let unvalidated_txs = self
            .db
            .transact("find_unvalidated_transactions", move |conn| {
                find_unvalidated_transactions(conn, &proposed_tx_ids)
            })
            .await
            .map_err(ValidatorError::DatabaseError)?;

        // All proposed transactions must have been validated.
        if !unvalidated_txs.is_empty() {
            return Err(ValidatorError::UnvalidatedTransactions(unvalidated_txs));
        }

        // Build the block header.
        let (proposed_header, proposed_body) = proposed_block
            .into_header_and_body()
            .map_err(ValidatorError::BlockBuildingFailed)?;

        miden_span_record!(
            block.number = proposed_header.block_num().as_u32(),
            block.commitment = %proposed_header.commitment(),
        );

        // If the proposed block has the same block number as the current chain tip, this is a
        // replacement block. Validate it against the previous block header.
        let prev = if proposed_header.block_num() == chain_tip.block_num() {
            // The genesis block cannot be replaced (genesis block has no parent).
            let prev_block_num =
                chain_tip.block_num().parent().ok_or(ValidatorError::NoPrevBlockHeader)?;
            self.db
                .query("load_block_header", move |conn| load_block_header(conn, prev_block_num))
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

        // Check that the block's validator key is set to our own.
        //
        // Otherwise we could be signing a block for a different key, making the
        // signature invalid.
        let signing_key = self.signer.public_key();
        if &signing_key != proposed_header.validator_key() {
            return Err(ValidatorError::ValidatorKeyMismatch {
                expected: proposed_header.validator_key().clone(),
                actual: signing_key,
            });
        }

        let signature = self.sign_header(&proposed_header).await?;

        // Back up the signed block to disk.
        let signed_block = SignedBlock::new_unchecked(proposed_header, proposed_body, signature);
        self.block_store
            .save_block(signed_block.header().block_num(), &signed_block.to_bytes())
            .await
            .map_err(ValidatorError::BlockBackupFailed)?;

        let (header, _, signature) = signed_block.into_parts();
        Ok((signature, header))
    }

    /// Signs a block header using the validator's signer.
    #[miden_instrument(
        target = COMPONENT,
        name = "sign_block",
        skip_all,
        err,
        fields(
            block.number = header.block_num().as_u32(),
        ),
    )]
    async fn sign_header(&self, header: &BlockHeader) -> Result<Signature, ValidatorError> {
        self.signer
            .sign(header)
            .await
            .map_err(|err| ValidatorError::BlockSigningFailed(err.to_string()))
    }
}
