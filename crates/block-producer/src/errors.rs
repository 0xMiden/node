use miden_node_persistence::PersistenceError;
use miden_node_proto::domain::sequencer::TransactionAuthenticationError;
use miden_node_proto::errors::GrpcError;
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::asset::AssetId;
use miden_protocol::batch::BatchId;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{NoteId, Nullifier};
use miden_protocol::transaction::TransactionId;
use thiserror::Error;

use crate::mempool::MempoolPoisonError;

// Proof scheduler errors
// =================================================================================================

#[derive(Debug, Error)]
pub enum ProofSchedulerError {
    #[error("no proving inputs found for block {0}")]
    MissingProvingInputs(BlockNumber),
    #[error("failed to deserialize proving inputs for block")]
    DeserializationFailed(#[source] PersistenceError),
}

// Add transaction and add user batch errors
// =================================================================================================

#[derive(Debug, Error, GrpcError)]
pub enum MempoolSubmissionError {
    #[error("failed to read state from the store")]
    #[grpc(internal)]
    StoreStateReadFailed(#[source] anyhow::Error),

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

/// Batch failures that either stop the worker or roll back its selected transactions.
#[derive(Debug, Error)]
pub enum BuildBatchError {
    #[error("mempool lock is poisoned")]
    MempoolPoisoned(#[from] MempoolPoisonError),
    #[error(transparent)]
    Failed(#[from] anyhow::Error),
}

// Block building errors
// =================================================================================================

/// Block failures that either stop production or roll back the selected batches.
#[derive(Debug, Error)]
pub enum BuildBlockError {
    #[error(
        "Desync detected between block-producer's chain tip {local_chain_tip} and the store's {store_chain_tip}"
    )]
    Desync {
        local_chain_tip: BlockNumber,
        store_chain_tip: BlockNumber,
    },
    #[error("mempool lock is poisoned")]
    MempoolPoisoned(#[from] MempoolPoisonError),
    #[error(transparent)]
    Failed(#[from] anyhow::Error),
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
            anyhow::anyhow!("private database data")
                .context("failed to get transaction inputs from store"),
        ));

        assert_eq!(status.code(), Code::Internal);
        assert_eq!(status.details(), &[0]);
        assert_eq!(status.message(), "Internal error");
    }
}
