use std::any::type_name;
use std::io;

use deadpool_sync::InteractError;
use miden_node_proto::domain::account::NetworkAccountError;
use miden_node_proto::domain::block::InvalidBlockRange;
use miden_node_proto::errors::{ConversionError, GrpcError};
use miden_node_utils::ErrorReport;
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
    FeeError,
    NoteError,
    NullifierTreeError,
    StorageMapError,
};
use miden_protocol::note::{NoteId, Nullifier};
use miden_protocol::transaction::OutputNote;
use thiserror::Error;
use tokio::sync::oneshot::error::RecvError;
use tonic::Status;

use crate::db::manager::ConnectionManagerError;
use crate::db::models::conv::DatabaseTypeConversionError;
use crate::inner_forest::{InnerForestError, WitnessError};

// DATABASE ERRORS
// =================================================================================================

#[derive(Debug, Error)]
pub enum DatabaseError {
    // ERRORS WITH AUTOMATIC CONVERSIONS FROM NESTED ERROR TYPES
    // ---------------------------------------------------------------------------------------------
    #[error("account is incomplete")]
    AccountIncomplete,
    #[error("account error")]
    AccountError(#[from] AccountError),
    #[error("account delta error")]
    AccountDeltaError(#[from] AccountDeltaError),
    #[error("asset vault error")]
    AssetVaultError(#[from] AssetVaultError),
    #[error("asset error")]
    AssetError(#[from] AssetError),
    #[error("closed channel")]
    ClosedChannel(#[from] RecvError),
    #[error("deserialization failed")]
    DeserializationError(#[from] DeserializationError),
    #[error("hex parsing error")]
    FromHexError(#[from] hex::FromHexError),
    #[error("I/O error")]
    IoError(#[from] io::Error),
    #[error("merkle error")]
    MerkleError(#[from] MerkleError),
    #[error("network account error")]
    NetworkAccountError(#[from] NetworkAccountError),
    #[error("note error")]
    NoteError(#[from] NoteError),
    #[error("storage map error")]
    StorageMapError(#[from] StorageMapError),
    #[error("setup deadpool connection pool failed")]
    Deadpool(#[from] deadpool::managed::PoolError<deadpool_diesel::Error>),
    #[error("setup deadpool connection pool failed")]
    ConnectionPoolObtainError(#[from] Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error(transparent)]
    Diesel(#[from] diesel::result::Error),
    #[error("sqlite FFI boundary NUL termination error (not much you can do, file an issue)")]
    DieselSqliteFfi(#[from] std::ffi::NulError),
    #[error(transparent)]
    DeadpoolDiesel(#[from] deadpool_diesel::Error),
    #[error(transparent)]
    PoolRecycle(#[from] deadpool::managed::RecycleError<deadpool_diesel::Error>),
    #[error("summing over column {column} of table {table} exceeded {limit}")]
    ColumnSumExceedsLimit {
        table: &'static str,
        column: &'static str,
        limit: &'static str,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },
    #[error(transparent)]
    QueryParamLimit(#[from] QueryLimitError),
    #[error("conversion from SQL to rust type {to} failed")]
    ConversionSqlToRust {
        #[source]
        inner: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
        to: &'static str,
    },

    // OTHER ERRORS
    // ---------------------------------------------------------------------------------------------
    #[error("account commitment mismatch (expected {expected}, but calculated is {calculated})")]
    AccountCommitmentsMismatch { expected: Word, calculated: Word },
    #[error("account {0} not found")]
    AccountNotFoundInDb(AccountId),
    #[error("account {0} state at block height {1} not found")]
    AccountAtBlockHeightNotFoundInDb(AccountId, BlockNumber),
    #[error("block {0} not found in database")]
    BlockNotFound(BlockNumber),
    #[error("historical block {block_num} not available: {reason}")]
    HistoricalBlockNotAvailable { block_num: BlockNumber, reason: String },
    #[error("accounts {0:?} not found")]
    AccountsNotFoundInDb(Vec<AccountId>),
    #[error("account {0} is not on the chain")]
    AccountNotPublic(AccountId),
    #[error("invalid block parameters: block_from ({from}) > block_to ({to})")]
    InvalidBlockRange { from: BlockNumber, to: BlockNumber },
    #[error("invalid storage slot type: {0}")]
    InvalidStorageSlotType(i32),
    #[error("data corrupted: {0}")]
    DataCorrupted(String),
    #[error("SQLite pool interaction failed: {0}")]
    InteractError(String),
    #[error("invalid Felt: {0}")]
    InvalidFelt(String),
    #[error(
        "unsupported database version. There is no migration chain from/to this version. \
        Remove all database files and try again."
    )]
    UnsupportedDatabaseVersion,
    #[error("schema verification failed")]
    SchemaVerification(#[from] SchemaVerificationError),
    #[error(transparent)]
    ConnectionManager(#[from] ConnectionManagerError),
    #[error(transparent)]
    SqlValueConversion(#[from] DatabaseTypeConversionError),
    #[error("Not implemented: {0}")]
    NotImplemented(String),
    #[error("storage root not found for account {account_id}, slot {slot_name}, block {block_num}")]
    StorageRootNotFound {
        account_id: AccountId,
        slot_name: String,
        block_num: BlockNumber,
    },
}

impl DatabaseError {
    /// Converts from `InteractError`
    ///
    /// Note: Required since `InteractError` has at least one enum
    /// variant that is _not_ `Send + Sync` and hence prevents the
    /// `Sync` auto implementation.
    /// This does an internal conversion to string while maintaining
    /// convenience.
    ///
    /// Using `MSG` as const so it can be called as
    /// `.map_err(DatabaseError::interact::<"Your message">)`
    pub fn interact(msg: &(impl ToString + ?Sized), e: &InteractError) -> Self {
        let msg = msg.to_string();
        Self::InteractError(format!("{msg} failed: {e:?}"))
    }

    /// Failed to convert an SQL entry to a rust representation
    pub fn conversiont_from_sql<RT, E, MaybeE>(err: MaybeE) -> DatabaseError
    where
        MaybeE: Into<Option<E>>,
        E: std::error::Error + Send + Sync + 'static,
    {
        DatabaseError::ConversionSqlToRust {
            inner: err.into().map(|err| Box::new(err) as Box<dyn std::error::Error + Send + Sync>),
            to: type_name::<RT>(),
        }
    }
}

impl From<DatabaseError> for Status {
    fn from(err: DatabaseError) -> Self {
        match err {
            DatabaseError::AccountNotFoundInDb(_)
            | DatabaseError::AccountsNotFoundInDb(_)
            | DatabaseError::AccountNotPublic(_) => Status::not_found(err.to_string()),

            _ => Status::internal(err.to_string()),
        }
    }
}

// INITIALIZATION ERRORS
// =================================================================================================

#[derive(Error, Debug)]
pub enum StateInitializationError {
    #[error("account tree IO error: {0}")]
    AccountTreeIoError(String),
    #[error("nullifier tree IO error: {0}")]
    NullifierTreeIoError(String),
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
    #[error("failed to load database")]
    DatabaseLoadError(#[from] DatabaseSetupError),
    #[error("inner forest error")]
    InnerForestError(#[from] InnerForestError),
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
    #[error("public account {0} is missing details in database")]
    PublicAccountMissingDetails(AccountId),
    #[error("failed to convert account to delta: {0}")]
    AccountToDeltaConversionFailed(String),
}

#[derive(Debug, Error)]
pub enum DatabaseSetupError {
    #[error("I/O error")]
    Io(#[from] io::Error),
    #[error("database error")]
    Database(#[from] DatabaseError),
    #[error("genesis block error")]
    GenesisBlock(#[from] GenesisError),
    #[error("pool build error")]
    PoolBuild(#[from] deadpool::managed::BuildError),
    #[error("Setup deadpool connection pool failed")]
    Pool(#[from] deadpool::managed::PoolError<deadpool_diesel::Error>),
}

#[derive(Debug, Error)]
pub enum GenesisError {
    // ERRORS WITH AUTOMATIC CONVERSIONS FROM NESTED ERROR TYPES
    // ---------------------------------------------------------------------------------------------
    #[error("database error")]
    Database(#[from] DatabaseError),
    #[error("failed to build genesis account tree")]
    AccountTree(#[source] AccountTreeError),
    #[error("failed to deserialize genesis file")]
    GenesisFileDeserialization(#[from] DeserializationError),
    #[error("fee cannot be created")]
    Fee(#[from] FeeError),
    #[error("failed to build account delta from account")]
    AccountDelta(AccountError),
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
    #[error("inner forest error")]
    InnerForestError(#[from] InnerForestError),

    // OTHER ERRORS
    // ---------------------------------------------------------------------------------------------
    #[error("block applying was cancelled because of closed channel on database side")]
    ClosedChannel(#[from] RecvError),
    #[error("concurrent write detected")]
    ConcurrentWrite,
    #[error("database doesn't have any block header data")]
    DbBlockHeaderEmpty,
    #[error("database update failed: {0}")]
    DbUpdateTaskFailed(String),
}

impl From<ApplyBlockError> for Status {
    fn from(err: ApplyBlockError) -> Self {
        match err {
            ApplyBlockError::InvalidBlockError(_) => Status::invalid_argument(err.as_report()),

            _ => Status::internal(err.as_report()),
        }
    }
}

#[derive(Error, Debug, GrpcError)]
pub enum GetBlockHeaderError {
    #[error("database error")]
    #[grpc(internal)]
    DatabaseError(#[from] DatabaseError),
    #[error("error retrieving the merkle proof for the block")]
    #[grpc(internal)]
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

#[derive(Error, Debug, GrpcError)]
pub enum NoteSyncError {
    #[error("database error")]
    #[grpc(internal)]
    DatabaseError(#[from] DatabaseError),
    #[error("block headers table is empty")]
    #[grpc(internal)]
    EmptyBlockHeadersTable,
    #[error("error retrieving the merkle proof for the block")]
    #[grpc(internal)]
    MmrError(#[from] MmrError),
    #[error("invalid block range")]
    InvalidBlockRange(#[from] InvalidBlockRange),
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

// SYNC NULLIFIERS ERRORS
// ================================================================================================

#[derive(Debug, Error, GrpcError)]
pub enum SyncNullifiersError {
    #[error("database error")]
    #[grpc(internal)]
    DatabaseError(#[from] DatabaseError),
    #[error("invalid block range")]
    InvalidBlockRange(#[from] InvalidBlockRange),
    #[error("unsupported prefix length: {0} (only 16-bit prefixes are supported)")]
    InvalidPrefixLength(u32),
    #[error("malformed nullifier prefix")]
    DeserializationFailed(#[from] ConversionError),
}

// SYNC ACCOUNT VAULT ERRORS
// ================================================================================================

#[derive(Debug, Error, GrpcError)]
pub enum SyncAccountVaultError {
    #[error("database error")]
    #[grpc(internal)]
    DatabaseError(#[from] DatabaseError),
    #[error("invalid block range")]
    InvalidBlockRange(#[from] InvalidBlockRange),
    #[error("malformed account ID")]
    DeserializationFailed(#[from] ConversionError),
    #[error("account {0} is not public")]
    AccountNotPublic(AccountId),
}

// SYNC STORAGE MAPS ERRORS
// ================================================================================================

#[derive(Debug, Error, GrpcError)]
pub enum SyncAccountStorageMapsError {
    #[error("database error")]
    #[grpc(internal)]
    DatabaseError(#[from] DatabaseError),
    #[error("invalid block range")]
    InvalidBlockRange(#[from] InvalidBlockRange),
    #[error("malformed account ID")]
    DeserializationFailed(#[from] ConversionError),
    #[error("account {0} not found")]
    AccountNotFound(AccountId),
    #[error("account {0} is not public")]
    AccountNotPublic(AccountId),
}

// GET NETWORK ACCOUNT IDS
// ================================================================================================

#[derive(Debug, Error, GrpcError)]
pub enum GetNetworkAccountIdsError {
    #[error("database error")]
    #[grpc(internal)]
    DatabaseError(#[from] DatabaseError),
    #[error("invalid block range")]
    InvalidBlockRange(#[from] InvalidBlockRange),
    #[error("malformed nullifier prefix")]
    DeserializationFailed(#[from] ConversionError),
}

// GET BLOCK BY NUMBER ERRORS
// ================================================================================================

#[derive(Debug, Error, GrpcError)]
pub enum GetBlockByNumberError {
    #[error("database error")]
    #[grpc(internal)]
    DatabaseError(#[from] DatabaseError),
    #[error("malformed block number")]
    DeserializationFailed(#[from] DeserializationError),
}

// GET NOTES BY ID ERRORS
// ================================================================================================

#[derive(Debug, Error, GrpcError)]
pub enum GetNotesByIdError {
    #[error("database error")]
    #[grpc(internal)]
    DatabaseError(#[from] DatabaseError),
    #[error("malformed note ID")]
    DeserializationFailed(#[from] ConversionError),
    #[error("note {0} not found")]
    NoteNotFound(NoteId),
    #[error("note {0} is not public")]
    NoteNotPublic(NoteId),
}

// GET NOTE SCRIPT BY ROOT ERRORS
// ================================================================================================

#[derive(Debug, Error, GrpcError)]
pub enum GetNoteScriptByRootError {
    #[error("database error")]
    #[grpc(internal)]
    DatabaseError(#[from] DatabaseError),
    #[error("malformed script root")]
    DeserializationFailed(#[from] ConversionError),
    #[error("script with given root not found")]
    ScriptNotFound,
}

// CHECK NULLIFIERS ERRORS
// ================================================================================================

#[derive(Debug, Error, GrpcError)]
pub enum CheckNullifiersError {
    #[error("database error")]
    #[grpc(internal)]
    DatabaseError(#[from] DatabaseError),
    #[error("malformed nullifier")]
    DeserializationFailed(#[from] ConversionError),
}

// SYNC TRANSACTIONS ERRORS
// ================================================================================================

#[derive(Debug, Error, GrpcError)]
pub enum SyncTransactionsError {
    #[error("database error")]
    #[grpc(internal)]
    DatabaseError(#[from] DatabaseError),
    #[error("invalid block range")]
    InvalidBlockRange(#[from] InvalidBlockRange),
    #[error("malformed account ID")]
    DeserializationFailed(#[from] ConversionError),
    #[error("account {0} not found")]
    AccountNotFound(AccountId),
    #[error("failed to retrieve witness")]
    WitnessError(#[from] WitnessError),
}

#[derive(Debug, Error, GrpcError)]
pub enum GetWitnessesError {
    #[error("malformed request")]
    DeserializationFailed(#[from] ConversionError),
    #[error("failed to retrieve witness")]
    WitnessError(#[from] WitnessError),
}

// SCHEMA VERIFICATION ERRORS
// =================================================================================================

/// Errors that can occur during schema verification.
#[derive(Debug, Error)]
pub enum SchemaVerificationError {
    #[error("failed to create in-memory reference database")]
    InMemoryDbCreation(#[source] diesel::ConnectionError),
    #[error("failed to apply migrations to reference database")]
    MigrationApplication(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("failed to extract schema from database")]
    SchemaExtraction(#[source] diesel::result::Error),
    #[error(
        "schema mismatch: expected {expected_count} objects, found {actual_count} \
         ({missing_count} missing, {extra_count} unexpected)"
    )]
    Mismatch {
        expected_count: usize,
        actual_count: usize,
        missing_count: usize,
        extra_count: usize,
    },
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
        DatabaseSetupError,
        DeserializationError,
        GenesisError,
        NetworkAccountError,
        NoteError,
        RecvError,
        StateInitializationError,
    };

    /// Ensure all enum variants remain compat with the desired
    /// trait bounds. Otherwise one gets very unwieldy errors.
    #[allow(dead_code)]
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
        ensure_is_error::<NetworkAccountError>(PhantomData);
        ensure_is_error::<NoteError>(PhantomData);
        ensure_is_error::<hex::FromHexError>(PhantomData);
        ensure_is_error::<deadpool::managed::PoolError<deadpool_diesel::Error>>(PhantomData);
        ensure_is_error::<diesel::result::Error>(PhantomData);
        ensure_is_error::<deadpool_diesel::Error>(PhantomData);
        ensure_is_error::<deadpool::managed::RecycleError<deadpool_diesel::Error>>(PhantomData);

        ensure_is_error::<DatabaseError>(PhantomData);
        ensure_is_error::<DatabaseSetupError>(PhantomData);
        ensure_is_error::<diesel::result::Error>(PhantomData);
        ensure_is_error::<GenesisError>(PhantomData);
        ensure_is_error::<StateInitializationError>(PhantomData);
        ensure_is_error::<deadpool::managed::PoolError<deadpool_diesel::Error>>(PhantomData);
    }
}
