use core::error::Error as CoreError;

use miden_node_proto::errors::GrpcError;
use miden_node_store::{
    ApplyBlockWithProvingInputsError,
    DatabaseError,
    GetBlockHeaderError,
    GetBlockInclusionProofsError,
    GetNoteInclusionProofsError,
};
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::crypto::utils::DeserializationError;
use miden_protocol::errors::{ProposedBatchError, ProposedBlockError, ProvenBatchError};
use miden_protocol::note::Nullifier;
use miden_protocol::transaction::TransactionId;
use thiserror::Error;

use crate::batch_builder::RemoteProverError;
use crate::mempool::MempoolPoisonError;
use crate::validator::ValidatorError;

// Proof scheduler errors
// =================================================================================================

#[derive(Debug, Error)]
pub enum ProofSchedulerError {
    #[error("no proving inputs found for block {0}")]
    MissingProvingInputs(BlockNumber),
    #[error("failed to deserialize proving inputs for block")]
    DeserializationFailed(#[source] DeserializationError),
}

// Add transaction and add user batch errors
// =================================================================================================

#[derive(Debug, Error, GrpcError)]
pub enum MempoolSubmissionError {
    #[error("failed to read state from the store")]
    #[grpc(internal)]
    StoreStateReadFailed(#[source] StoreError),

    #[error("failed to authenticate transaction")]
    #[grpc(internal)]
    AuthenticationFailed(#[source] StateConflict),

    #[error("transaction input data from block {input_block} exceeds the chain tip {chain_tip}")]
    #[grpc(internal)]
    FutureInputs {
        input_block: BlockNumber,
        chain_tip: BlockNumber,
    },

    #[error(
        "transaction input data from block {input_block} is rejected as stale because it is older than the limit of {stale_limit}"
    )]
    #[grpc(internal)]
    StaleInputs {
        input_block: BlockNumber,
        stale_limit: BlockNumber,
    },

    #[error(
        "transaction expired at block height {expired_at} but the block height limit was {limit}"
    )]
    Expired {
        expired_at: BlockNumber,
        limit: BlockNumber,
    },

    #[error("transaction conflicts with current mempool state")]
    StateConflict(#[source] StateConflict),

    #[error("the mempool is at capacity")]
    CapacityExceeded,

    #[error("transaction {transaction_id} does not contain a non-zero TX_FEE output note")]
    MissingFee { transaction_id: TransactionId },

    #[error("transaction {transaction_id} consumes in-flight TX_FEE notes: {note_ids:?}")]
    ConsumesInflightFeeNotes {
        transaction_id: TransactionId,
        note_ids: Vec<Word>,
    },

    #[error("mempool lock is poisoned")]
    #[grpc(internal)]
    MempoolPoisoned(#[source] MempoolPoisonError),
}

// Mempool submission conflicts with current state
// =================================================================================================

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StateConflict {
    #[error("nullifiers already exist: {0:?}")]
    NullifiersAlreadyExist(Vec<Nullifier>),
    #[error("output notes already exist: {0:?}")]
    OutputNotesAlreadyExist(Vec<Word>),
    #[error("unauthenticated input notes are unknown: {0:?}")]
    UnauthenticatedNotesMissing(Vec<Word>),
    #[error(
        "initial account commitment {expected} does not match the current commitment {current} for account {account}"
    )]
    AccountCommitmentMismatch {
        account: AccountId,
        expected: Word,
        current: Word,
    },
}

// Batch building errors
// =================================================================================================

/// Error encountered while building a batch.
#[derive(Debug, Error)]
pub enum BuildBatchError {
    #[error("batch proving task panic'd")]
    JoinError(#[from] tokio::task::JoinError),

    #[error("failed to fetch batch inputs from store")]
    FetchBatchInputsFailed(#[source] StoreError),

    #[error("failed to build proposed transaction batch")]
    ProposeBatchError(#[source] ProposedBatchError),

    #[error("failed to prove proposed transaction batch")]
    ProveBatchError(#[source] ProvenBatchError),

    #[error("failed to prove batch with remote prover")]
    RemoteProverClientError(#[source] RemoteProverError),

    #[error("batch proof security level is too low: {0} < {1}")]
    SecurityLevelTooLow(u32, u32),

    #[error("mempool lock is poisoned")]
    MempoolPoisoned(#[source] MempoolPoisonError),
}

// Block building errors
// =================================================================================================

#[derive(Debug, Error)]
pub enum BuildBlockError {
    #[error("failed to apply block to store")]
    StoreApplyBlockFailed(#[source] StoreError),
    #[error("failed to fetch block inputs from store")]
    FetchBlockInputsFailed(#[source] StoreError),
    #[error(
        "Desync detected between block-producer's chain tip {local_chain_tip} and the store's {store_chain_tip}"
    )]
    Desync {
        local_chain_tip: BlockNumber,
        store_chain_tip: BlockNumber,
    },
    #[error("failed to propose block")]
    ProposeBlockFailed(#[source] ProposedBlockError),
    #[error("failed to validate block")]
    ValidateBlockFailed(#[source] Box<ValidatorError>),
    #[error("block signatures are invalid")]
    InvalidSignature,
    #[error(
        "no signature received for the validator key at position {position} of the parent's validator set"
    )]
    MissingValidatorSignature { position: usize },
    #[error(
        "block commitment signed by a validator {validator} does not match the block proposed by the sequencer {sequencer}"
    )]
    BlockCommitmentMismatch { validator: Word, sequencer: Word },

    #[error("mempool lock is poisoned")]
    MempoolPoisoned(#[source] MempoolPoisonError),

    /// Custom error variant for errors not covered by the other variants.
    #[error("{error_msg}")]
    Other {
        error_msg: Box<str>,
        source: Option<Box<dyn CoreError + Send + Sync + 'static>>,
    },
}

impl BuildBlockError {
    /// Creates a custom error using the [`BuildBlockError::Other`] variant from an error message.
    pub fn other(message: impl Into<String>) -> Self {
        let message: String = message.into();
        Self::Other { error_msg: message.into(), source: None }
    }
}

// Store errors
// =================================================================================================

/// Errors returned by the store state.
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("account Id prefix already exists: {0}")]
    DuplicateAccountIdPrefix(AccountId),
    #[error("failed to get transaction inputs from store")]
    GetTransactionInputsFailed(#[source] DatabaseError),
    #[error("failed to get block inclusion proofs from store")]
    GetBlockInclusionProofsFailed(#[source] GetBlockInclusionProofsError),
    #[error("failed to get block header from store")]
    GetBlockHeaderFailed(#[source] GetBlockHeaderError),
    #[error("failed to get note inclusion proofs from store")]
    GetNoteInclusionProofsFailed(#[source] GetNoteInclusionProofsError),
    #[error("failed to apply block to store")]
    ApplyBlockFailed(#[source] ApplyBlockWithProvingInputsError),
}
