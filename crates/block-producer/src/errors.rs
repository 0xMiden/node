use core::error::Error as CoreError;

use miden_node_proto::domain::sequencer::TransactionAuthenticationError;
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
use miden_protocol::asset::AssetId;
use miden_protocol::batch::BatchId;
use miden_protocol::block::BlockNumber;
use miden_protocol::crypto::utils::DeserializationError;
use miden_protocol::errors::{ProposedBatchError, ProposedBlockError, ProvenBatchError};
use miden_protocol::note::{NoteId, Nullifier};
use miden_protocol::transaction::TransactionId;
use thiserror::Error;

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

    #[error("transaction {transaction_id} does not contain a canonical TX_FEE output note")]
    MissingFee { transaction_id: TransactionId },

    #[error("transaction {transaction_id} consumes in-flight TX_FEE notes: {note_ids:?}")]
    ConsumesInflightFeeNotes {
        transaction_id: TransactionId,
        note_ids: Vec<NoteId>,
    },

    #[error("mempool lock is poisoned")]
    #[grpc(internal)]
    MempoolPoisoned(#[source] MempoolPoisonError),

    #[error(
        "transaction {transaction_id} must use only the native asset {fee_asset_id} in each TX_FEE output note"
    )]
    InvalidFeeAsset {
        transaction_id: TransactionId,
        fee_asset_id: AssetId,
    },

    #[error("user batch proof ID {proof_id} does not match transaction batch ID {batch_id}")]
    BatchIdMismatch { proof_id: BatchId, batch_id: BatchId },

    // Keep new client errors at the end to preserve the gRPC error codes.
    #[error("failed to authenticate transaction")]
    AuthenticationFailed(#[source] StateConflict),
}

// Mempool submission conflicts with current state
// =================================================================================================

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StateConflict {
    #[error("invalid transaction authentication inputs")]
    InvalidAuthenticationInputs(#[source] TransactionAuthenticationError),
    #[error("nullifiers already exist: {0:?}")]
    NullifiersAlreadyExist(Vec<Nullifier>),
    #[error("output notes already exist: {0:?}")]
    OutputNotesAlreadyExist(Vec<NoteId>),
    #[error("unauthenticated input notes are unknown: {0:?}")]
    UnauthenticatedNotesMissing(Vec<NoteId>),
    #[error(
        "initial account commitment {expected} does not match the current commitment {current} for account {account}"
    )]
    AccountCommitmentMismatch {
        account: AccountId,
        expected: Word,
        current: Word,
    },
}

impl From<TransactionAuthenticationError> for StateConflict {
    fn from(error: TransactionAuthenticationError) -> Self {
        match error {
            TransactionAuthenticationError::NullifiersAlreadyExist(nullifiers) => {
                Self::NullifiersAlreadyExist(nullifiers)
            },
            error => Self::InvalidAuthenticationInputs(error),
        }
    }
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

    #[error("failed to build the batch fee transaction")]
    BuildBatchFeeTransaction(#[source] anyhow::Error),

    #[error("failed to validate the batch fee transaction")]
    ValidateBatchFeeTransaction(#[source] anyhow::Error),

    #[error("failed to prove proposed transaction batch")]
    ProveBatchError(#[source] ProvenBatchError),

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
    #[error("failed to get protocol configuration from store")]
    GetProtocolConfigFailed(#[source] DatabaseError),
    #[error("failed to get note inclusion proofs from store")]
    GetNoteInclusionProofsFailed(#[source] GetNoteInclusionProofsError),
    #[error("failed to apply block to store")]
    ApplyBlockFailed(#[source] ApplyBlockWithProvingInputsError),
}

#[cfg(test)]
mod tests {
    use tonic::{Code, Status};

    use super::*;

    #[test]
    fn authentication_failure_returns_client_error_with_cause() {
        let error = MempoolSubmissionError::AuthenticationFailed(
            StateConflict::NullifiersAlreadyExist(vec![Nullifier::from_raw(Word::default())]),
        );
        let status = Status::from(error);

        assert_eq!(status.code(), Code::InvalidArgument);
        assert_eq!(status.details(), &[8]);
        assert!(status.message().contains("failed to authenticate transaction"));
        assert!(status.message().contains("nullifiers already exist"));
    }

    #[test]
    fn submission_error_codes_remain_stable() {
        for (error, code) in [
            (MempoolSubmissionError::Expired { expired_at: 1.into(), limit: 2.into() }, 1),
            (
                MempoolSubmissionError::StateConflict(StateConflict::NullifiersAlreadyExist(vec![
                    Nullifier::from_raw(Word::default()),
                ])),
                2,
            ),
            (MempoolSubmissionError::CapacityExceeded, 3),
        ] {
            let status = Status::from(error);
            assert_eq!(status.code(), Code::InvalidArgument);
            assert_eq!(status.details(), &[code]);
        }
    }

    #[test]
    fn internal_submission_failure_hides_cause() {
        let status = Status::from(MempoolSubmissionError::StoreStateReadFailed(
            StoreError::GetTransactionInputsFailed(DatabaseError::DataCorrupted(
                "private database data".into(),
            )),
        ));

        assert_eq!(status.code(), Code::Internal);
        assert_eq!(status.details(), &[0]);
        assert_eq!(status.message(), "Internal error");
    }
}
