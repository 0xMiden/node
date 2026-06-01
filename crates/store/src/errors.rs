use std::io;

use miden_node_proto::domain::block::InvalidBlockRange;
use miden_node_proto::errors::ConversionError;
use miden_node_utils::limiter::QueryLimitError;
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::crypto::merkle::MerkleError;
use miden_protocol::crypto::merkle::mmr::MmrError;
use miden_protocol::crypto::utils::DeserializationError;
use miden_protocol::errors::{
    AccountDeltaError,
    AccountError,
    AccountTreeError,
    AssetError,
    AssetVaultError,
    NoteError,
    NullifierTreeError,
    StorageMapError,
};
use miden_protocol::note::Nullifier;
use miden_protocol::transaction::OutputNote;
use thiserror::Error;
use tokio::sync::oneshot::error::RecvError;

use crate::account_state_forest::AccountStateForestError;
use crate::db::models::conv::DatabaseTypeConversionError;

// DATABASE ERRORS
// =================================================================================================

#[derive(Debug, Error)]
pub enum DatabaseError {
    // ERRORS WITH AUTOMATIC CONVERSIONS FROM NESTED ERROR TYPES
    // ---------------------------------------------------------------------------------------------
    #[error("account error")]
    AccountError(#[from] AccountError),
    #[error("asset vault error")]
    AssetVaultError(#[from] AssetVaultError),
    #[error("asset error")]
    AssetError(#[from] AssetError),
    #[error("closed channel")]
    ClosedChannel(#[from] RecvError),
    #[error("database error")]
    DatabaseError(#[from] miden_node_db::DatabaseError),
    #[error("deserialization failed")]
    DeserializationError(#[from] DeserializationError),
    #[error("I/O error")]
    IoError(#[from] io::Error),
    #[error("merkle error")]
    MerkleError(#[from] MerkleError),
    #[error("note error")]
    NoteError(#[from] NoteError),
    #[error("storage map error")]
    StorageMapError(#[from] StorageMapError),
    #[error(transparent)]
    Diesel(#[from] diesel::result::Error),
    #[error(transparent)]
    QueryParamLimit(#[from] QueryLimitError),

    // OTHER ERRORS
    // ---------------------------------------------------------------------------------------------
    #[error("account commitment mismatch (expected {expected}, but calculated is {calculated})")]
    AccountCommitmentsMismatch { expected: Word, calculated: Word },
    #[error("account {0} not found")]
    AccountNotFoundInDb(AccountId),
    #[error("accounts {0:?} not found")]
    AccountsNotFoundInDb(Vec<AccountId>),
    #[error("account {0} is not on the chain")]
    AccountNotPublic(AccountId),
    #[error("invalid block parameters: block_from ({from}) > block_to ({to})")]
    InvalidBlockRange { from: BlockNumber, to: BlockNumber },
    #[error("data corrupted: {0}")]
    DataCorrupted(String),
    #[error(transparent)]
    SqlValueConversion(#[from] DatabaseTypeConversionError),
    #[error("storage root not found for account {account_id}, slot {slot_name}, block {block_num}")]
    StorageRootNotFound {
        account_id: AccountId,
        slot_name: String,
        block_num: BlockNumber,
    },
}

// INITIALIZATION ERRORS
// =================================================================================================

#[derive(Error, Debug)]
pub enum StateInitializationError {
    #[error("account tree IO error: {0}")]
    AccountTreeIoError(String),
    #[error("nullifier tree IO error: {0}")]
    NullifierTreeIoError(String),
    #[error("account state forest IO error: {0}")]
    AccountStateForestIoError(String),
    #[error("database error")]
    DatabaseError(#[from] DatabaseError),
    #[error("failed to create nullifier tree")]
    FailedToCreateNullifierTree(#[from] NullifierTreeError),
    #[error("failed to create accounts tree")]
    FailedToCreateAccountsTree(#[source] AccountTreeError),
    #[error("failed to load data directory")]
    DataDirectoryLoadError(#[source] std::io::Error),
    #[error("failed to load block store")]
    BlockStoreLoadError(#[source] std::io::Error),
    #[error("failed to load proven tip")]
    ProvenTipLoadError(#[source] std::io::Error),
    #[error("failed to load database")]
    DatabaseLoadError(#[source] DatabaseError),
    #[error("account state forest error")]
    AccountStateForestError(#[from] AccountStateForestError),
    #[error(
        "{tree_name} SMT root ({tree_root:?}) does not match expected root from block {block_num} \
         ({block_root:?}). Delete the tree storage directories and restart the node to rebuild \
         from the database."
    )]
    TreeStorageDiverged {
        tree_name: &'static str,
        block_num: BlockNumber,
        tree_root: Word,
        block_root: Word,
    },
    #[error(
        "account state forest root ({forest_root}) does not match SQLite root \
         ({database_root}) for account {account_id}, slot {slot_name:?}. Delete the account \
         state forest storage directory and restart the node to rebuild from the database."
    )]
    AccountStateForestStorageDiverged {
        account_id: AccountId,
        slot_name: Option<String>,
        forest_root: Word,
        database_root: Word,
    },
    #[error("public account {0} is missing details in database")]
    PublicAccountMissingDetails(AccountId),
    #[error("failed to convert account to delta: {0}")]
    AccountToDeltaConversionFailed(String),
}

// ENDPOINT ERRORS
// =================================================================================================
#[derive(Error, Debug)]
pub enum InvalidBlockError {
    #[error("duplicated nullifiers {0:?}")]
    DuplicatedNullifiers(Vec<Nullifier>),
    #[error("invalid output note type: {0:?}")]
    InvalidOutputNoteType(Box<OutputNote>),
    #[error("invalid block tx commitment: expected {expected}, but got {actual}")]
    InvalidBlockTxCommitment { expected: Word, actual: Word },
    #[error("received invalid account tree root")]
    NewBlockInvalidAccountRoot,
    #[error("new block number must be 1 greater than the current block number")]
    NewBlockInvalidBlockNum {
        expected: BlockNumber,
        submitted: BlockNumber,
    },
    #[error("new block chain commitment is not consistent with chain MMR")]
    NewBlockInvalidChainCommitment,
    #[error("received invalid note root")]
    NewBlockInvalidNoteRoot,
    #[error("received invalid nullifier root")]
    NewBlockInvalidNullifierRoot,
    #[error("new block `prev_block_commitment` must match the chain's tip")]
    NewBlockInvalidPrevCommitment,
    #[error("nullifier in new block is already spent")]
    NewBlockNullifierAlreadySpent(#[source] NullifierTreeError),
    #[error("duplicate account ID prefix in new block")]
    NewBlockDuplicateAccountIdPrefix(#[source] AccountTreeError),
    #[error("failed to build note tree: {0}")]
    FailedToBuildNoteTree(String),
}

#[derive(Error, Debug)]
pub enum ApplyBlockError {
    // ERRORS WITH AUTOMATIC CONVERSIONS FROM NESTED ERROR TYPES
    // ---------------------------------------------------------------------------------------------
    #[error("database error")]
    DatabaseError(#[from] DatabaseError),
    #[error("I/O error")]
    IoError(#[from] io::Error),
    #[error("task join error")]
    TokioJoinError(#[from] tokio::task::JoinError),
    #[error("invalid block error")]
    InvalidBlockError(#[from] InvalidBlockError),
    #[error("account state forest error")]
    AccountStateForestError(#[from] AccountStateForestError),

    // OTHER ERRORS
    // ---------------------------------------------------------------------------------------------
    #[error("failed to send block to writer task: {0}")]
    WriterTaskSendFailed(String),
    #[error("writer task dropped the result channel")]
    WriterTaskRecvFailed(#[from] RecvError),
    #[error("database doesn't have any block header data")]
    DbBlockHeaderEmpty,
    #[error("database update failed: {0}")]
    DbUpdateTaskFailed(String),
}

#[derive(Error, Debug)]
pub enum ApplyBlockWithProvingInputsError {
    #[error("failed to save block proving inputs")]
    SaveProvingInputs(#[source] io::Error),
    #[error("failed to apply block")]
    ApplyBlock(#[source] ApplyBlockError),
}

#[derive(Error, Debug)]
pub enum GetBlockHeaderError {
    #[error("database error")]
    DatabaseError(#[from] DatabaseError),
    #[error("error retrieving the merkle proof for the block")]
    MmrError(#[from] MmrError),
}

#[derive(Error, Debug)]
pub enum GetBlockInputsError {
    #[error("failed to select note inclusion proofs")]
    SelectNoteInclusionProofError(#[source] DatabaseError),
    #[error("failed to select block headers")]
    SelectBlockHeaderError(#[source] DatabaseError),
    #[error(
        "highest block number {highest_block_number} referenced by a batch is newer than the latest block {latest_block_number}"
    )]
    UnknownBatchBlockReference {
        highest_block_number: BlockNumber,
        latest_block_number: BlockNumber,
    },
}

#[derive(Error, Debug)]
pub enum StateSyncError {
    #[error("database error")]
    DatabaseError(#[from] DatabaseError),
    #[error("block headers table is empty")]
    EmptyBlockHeadersTable,
    #[error("failed to build MMR delta")]
    FailedToBuildMmrDelta(#[from] MmrError),
}

impl From<diesel::result::Error> for StateSyncError {
    fn from(value: diesel::result::Error) -> Self {
        Self::DatabaseError(DatabaseError::from(value))
    }
}

#[derive(Error, Debug)]
pub enum NoteSyncError {
    #[error("database error")]
    DatabaseError(#[from] DatabaseError),
    #[error("database error")]
    UnderlyingDatabaseError(#[from] miden_node_db::DatabaseError),
    #[error("block headers table is empty")]
    EmptyBlockHeadersTable,
    #[error("error retrieving the merkle proof for the block")]
    MmrError(#[from] MmrError),
    #[error("invalid block range")]
    InvalidBlockRange(#[from] InvalidBlockRange),
    #[error("block_to ({block_to}) is greater than chain tip ({chain_tip})")]
    FutureBlock {
        chain_tip: BlockNumber,
        block_to: BlockNumber,
    },
    #[error("malformed note tags")]
    DeserializationFailed(#[from] ConversionError),
}

impl From<diesel::result::Error> for NoteSyncError {
    fn from(value: diesel::result::Error) -> Self {
        Self::DatabaseError(DatabaseError::from(value))
    }
}

#[derive(Error, Debug)]
pub enum GetCurrentBlockchainDataError {
    #[error("failed to retrieve block header")]
    ErrorRetrievingBlockHeader(#[source] DatabaseError),
    #[error("failed to instantiate MMR peaks")]
    InvalidPeaks(MmrError),
}

#[derive(Error, Debug)]
pub enum GetBatchInputsError {
    #[error("failed to select note inclusion proofs")]
    SelectNoteInclusionProofError(#[source] DatabaseError),
    #[error("failed to select block headers")]
    SelectBlockHeaderError(#[source] DatabaseError),
    #[error("set of blocks referenced by transactions is empty")]
    TransactionBlockReferencesEmpty,
    #[error(
        "highest block number {highest_block_num} referenced by a transaction is newer than the latest block {latest_block_num}"
    )]
    UnknownTransactionBlockReference {
        highest_block_num: BlockNumber,
        latest_block_num: BlockNumber,
    },
}

// GET ACCOUNT ERRORS
// ================================================================================================

#[derive(Debug, Error)]
pub enum GetAccountError {
    #[error("database error")]
    DatabaseError(#[from] DatabaseError),
    #[error("malformed request")]
    DeserializationFailed(#[from] ConversionError),
    #[error("account {0} not found at block {1}")]
    AccountNotFound(AccountId, BlockNumber),
    #[error("account {0} is not public")]
    AccountNotPublic(AccountId),
    #[error("block {0} is unknown")]
    UnknownBlock(BlockNumber),
    #[error("block {0} has been pruned")]
    BlockPruned(BlockNumber),
}

// Do not scope for `cfg(test)` - if it the traitbounds don't suffice the issue will already appear
// in the compilation of the library or binary, which would prevent getting to compiling the
// following code.
mod compile_tests {
    use std::marker::PhantomData;

    use super::{
        AccountDeltaError,
        AccountError,
        DatabaseError,
        DeserializationError,
        NoteError,
        RecvError,
        StateInitializationError,
    };

    /// Ensure all enum variants remain compat with the desired trait bounds. Otherwise one gets
    /// very unwieldy errors.
    #[expect(dead_code)]
    fn assumed_trait_bounds_upheld() {
        fn ensure_is_error<E>(_phony: PhantomData<E>)
        where
            E: std::error::Error + Send + Sync + 'static,
        {
        }

        ensure_is_error::<AccountError>(PhantomData);
        ensure_is_error::<AccountDeltaError>(PhantomData);
        ensure_is_error::<RecvError>(PhantomData);
        ensure_is_error::<DeserializationError>(PhantomData);
        ensure_is_error::<NoteError>(PhantomData);
        ensure_is_error::<hex::FromHexError>(PhantomData);
        ensure_is_error::<deadpool::managed::PoolError<deadpool_diesel::Error>>(PhantomData);
        ensure_is_error::<diesel::result::Error>(PhantomData);
        ensure_is_error::<deadpool_diesel::Error>(PhantomData);
        ensure_is_error::<deadpool::managed::RecycleError<deadpool_diesel::Error>>(PhantomData);

        ensure_is_error::<DatabaseError>(PhantomData);
        ensure_is_error::<diesel::result::Error>(PhantomData);
        ensure_is_error::<StateInitializationError>(PhantomData);
        ensure_is_error::<deadpool::managed::PoolError<deadpool_diesel::Error>>(PhantomData);
    }
}
