use core::error::Error as CoreError;

use miden_node_proto::errors::GrpcError;
use miden_node_store::{
    ApplyBlockWithProvingInputsError,
    DatabaseError,
    GetBatchInputsError,
    GetBlockInputsError,
};
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::crypto::utils::DeserializationError;
use miden_protocol::errors::{ProposedBatchError, ProposedBlockError, ProvenBatchError};
use miden_protocol::note::Nullifier;
use miden_remote_prover_client::RemoteProverClientError;
use thiserror::Error;
use tokio::task::JoinError;

use crate::mempool::MempoolPoisonError;
use crate::validator::ValidatorError;

// Block-producer errors
// =================================================================================================

#[derive(Debug, Error)]
pub enum BlockProducerError {
    /// A block-producer task completed although it should have ran indefinitely.
    #[error("task {task} completed unexpectedly")]
    UnexpectedTaskCompletion { task: String },

    /// A block-producer task panic'd.
    #[error("task {task} panic'd")]
    JoinError { task: String, source: JoinError },

    /// A block-producer task reported a transport error.
    #[error("task {task} failed")]
    TaskError { task: String, source: anyhow::Error },
}

// Proof scheduler errors
// =================================================================================================

#[derive(Debug, Error)]
pub enum ProofSchedulerError {
    #[error("no proving inputs found for block {0}")]
    MissingProvingInputs(BlockNumber),
    #[error("failed to deserialize proving inputs for block")]
    DeserializationFailed(#[source] DeserializationError),
    #[error("invalid remote prover endpoint: {0}")]
    InvalidProverEndpoint(String),
}

// Add transaction and add user batch errors
// =================================================================================================

#[derive(Debug, Error, GrpcError)]
pub enum MempoolSubmissionError {
    #[error("failed to read state from the store")]
    #[grpc(internal)]
    StoreStateReadFailed(#[source] StoreError),

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
    /// We sometimes randomly inject errors into the batch building process to test our failure
    /// responses.
    #[error("nothing actually went wrong, failure was injected on purpose")]
    InjectedFailure,

    #[error("batch proving task panic'd")]
    JoinError(#[from] tokio::task::JoinError),

    #[error("failed to fetch batch inputs from store")]
    FetchBatchInputsFailed(#[source] StoreError),

    #[error("failed to build proposed transaction batch")]
    ProposeBatchError(#[source] ProposedBatchError),

    #[error("failed to prove proposed transaction batch")]
    ProveBatchError(#[source] ProvenBatchError),

    #[error("failed to prove batch with remote prover")]
    RemoteProverClientError(#[source] RemoteProverClientError),

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
    #[error("failed to get block inputs from store")]
    GetBlockInputsFailed(#[source] StoreError),
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
    #[error("block signature is invalid")]
    InvalidSignature,

    #[error("mempool lock is poisoned")]
    MempoolPoisoned(#[source] MempoolPoisonError),

    /// We sometimes randomly inject errors into the batch building process to test our failure
    /// responses.

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
    #[error("failed to get batch inputs from store")]
    GetBatchInputsFailed(#[source] GetBatchInputsError),
    #[error("failed to get block inputs from store")]
    GetBlockInputsFailed(#[source] GetBlockInputsError),
    #[error("failed to apply block to store")]
    ApplyBlockFailed(#[source] ApplyBlockWithProvingInputsError),
}
