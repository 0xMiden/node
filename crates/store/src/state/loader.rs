//! Tree loading logic for the store state.
//!
//! This module handles loading and initializing the Merkle trees (account tree, nullifier tree,
//! and SMT forest) from storage backends. It supports different loading modes:
//!
//! - **Memory mode** (`rocksdb` feature disabled): Trees are rebuilt from the database on each
//!   startup.
//! - **Persistent mode** (`rocksdb` feature enabled): Trees are loaded from persistent storage if
//!   data exists, otherwise rebuilt from the database and persisted.

use std::future::Future;
use std::path::Path;

use miden_protocol::Word;
use miden_protocol::block::account_tree::{AccountTree, account_id_to_smt_key};
use miden_protocol::block::nullifier_tree::NullifierTree;
use miden_protocol::block::{BlockHeader, BlockNumber, Blockchain};
#[cfg(not(feature = "rocksdb"))]
use miden_protocol::crypto::merkle::smt::MemoryStorage;
use miden_protocol::crypto::merkle::smt::{LargeSmt, LargeSmtError, SmtStorage};
#[cfg(feature = "rocksdb")]
use tracing::info;
use tracing::instrument;
#[cfg(feature = "rocksdb")]
use {
    miden_crypto::merkle::smt::RocksDbStorage,
    miden_protocol::crypto::merkle::smt::RocksDbConfig,
};

use crate::COMPONENT;
use crate::db::Db;
use crate::errors::{DatabaseError, StateInitializationError};
use crate::inner_forest::InnerForest;

// CONSTANTS
// ================================================================================================

/// Directory name for the account tree storage within the data directory.
pub const ACCOUNT_TREE_STORAGE_DIR: &str = "accounttree";

/// Directory name for the nullifier tree storage within the data directory.
pub const NULLIFIER_TREE_STORAGE_DIR: &str = "nullifiertree";

// STORAGE TYPE ALIAS
// ================================================================================================

/// The storage backend for trees.
#[cfg(feature = "rocksdb")]
pub type TreeStorage = RocksDbStorage;
#[cfg(not(feature = "rocksdb"))]
pub type TreeStorage = MemoryStorage;

// ERROR CONVERSION
// ================================================================================================

/// Converts a `LargeSmtError` into a `StateInitializationError`.
pub fn account_tree_large_smt_error_to_init_error(e: LargeSmtError) -> StateInitializationError {
    use miden_node_utils::ErrorReport;
    match e {
        LargeSmtError::Merkle(merkle_error) => {
            StateInitializationError::DatabaseError(DatabaseError::MerkleError(merkle_error))
        },
        LargeSmtError::Storage(err) => {
            StateInitializationError::AccountTreeIoError(err.as_report())
        },
    }
}

// STORAGE LOADER TRAIT
// ================================================================================================

/// Trait for loading trees from storage.
///
/// For `MemoryStorage`, the tree is rebuilt from database entries on each startup.
/// For `RocksDbStorage`, the tree is loaded directly from disk (much faster for large trees).
///
/// Missing or corrupted storage is handled by the `verify_tree_consistency` check after loading,
/// which detects divergence between persistent storage and the database. If divergence is detected,
/// the user should manually delete the tree storage directories and restart the node.
pub trait StorageLoader: SmtStorage + Sized {
    /// Creates a storage backend for the given domain.
    fn create(data_dir: &Path, domain: &'static str) -> Result<Self, StateInitializationError>;

    /// Loads an account tree, either from persistent storage or by rebuilding from DB.
    fn load_account_tree(
        self,
        db: &mut Db,
    ) -> impl Future<Output = Result<AccountTree<LargeSmt<Self>>, StateInitializationError>> + Send;

    /// Loads a nullifier tree, either from persistent storage or by rebuilding from DB.
    fn load_nullifier_tree(
        self,
        db: &mut Db,
    ) -> impl Future<Output = Result<NullifierTree<LargeSmt<Self>>, StateInitializationError>> + Send;
}

// MEMORY STORAGE IMPLEMENTATION
// ================================================================================================

#[cfg(not(feature = "rocksdb"))]
impl StorageLoader for MemoryStorage {
    fn create(_data_dir: &Path, _domain: &'static str) -> Result<Self, StateInitializationError> {
        Ok(MemoryStorage::default())
    }

    async fn load_account_tree(
        self,
        db: &mut Db,
    ) -> Result<AccountTree<LargeSmt<Self>>, StateInitializationError> {
        let account_data = db.select_all_account_commitments().await?;
        let smt_entries = account_data
            .into_iter()
            .map(|(id, commitment)| (account_id_to_smt_key(id), commitment));
        let smt = LargeSmt::with_entries(self, smt_entries)
            .map_err(account_tree_large_smt_error_to_init_error)?;
        AccountTree::new(smt).map_err(StateInitializationError::FailedToCreateAccountsTree)
    }

    async fn load_nullifier_tree(
        self,
        db: &mut Db,
    ) -> Result<NullifierTree<LargeSmt<Self>>, StateInitializationError> {
        let nullifiers = db.select_all_nullifiers().await?;
        let entries = nullifiers.into_iter().map(|info| (info.nullifier, info.block_num));
        NullifierTree::with_storage_from_entries(self, entries)
            .map_err(StateInitializationError::FailedToCreateNullifierTree)
    }
}

// ROCKSDB STORAGE IMPLEMENTATION
// ================================================================================================

#[cfg(feature = "rocksdb")]
impl StorageLoader for RocksDbStorage {
    fn create(data_dir: &Path, domain: &'static str) -> Result<Self, StateInitializationError> {
        let storage_path = data_dir.join(domain);

        fs_err::create_dir_all(&storage_path)
            .map_err(|e| StateInitializationError::AccountTreeIoError(e.to_string()))?;
        RocksDbStorage::open(RocksDbConfig::new(storage_path))
            .map_err(|e| StateInitializationError::AccountTreeIoError(e.to_string()))
    }

    async fn load_account_tree(
        self,
        db: &mut Db,
    ) -> Result<AccountTree<LargeSmt<Self>>, StateInitializationError> {
        // If RocksDB storage has data, load from it directly
        let has_data = self
            .has_leaves()
            .map_err(|e| StateInitializationError::AccountTreeIoError(e.to_string()))?;
        if has_data {
            let smt = load_smt(self)?;
            return AccountTree::new(smt)
                .map_err(StateInitializationError::FailedToCreateAccountsTree);
        }

        info!(target: COMPONENT, "RocksDB account tree storage is empty, populating from SQLite");
        let account_data = db.select_all_account_commitments().await?;
        let smt_entries = account_data
            .into_iter()
            .map(|(id, commitment)| (account_id_to_smt_key(id), commitment));
        let smt = LargeSmt::with_entries(self, smt_entries)
            .map_err(account_tree_large_smt_error_to_init_error)?;
        AccountTree::new(smt).map_err(StateInitializationError::FailedToCreateAccountsTree)
    }

    async fn load_nullifier_tree(
        self,
        db: &mut Db,
    ) -> Result<NullifierTree<LargeSmt<Self>>, StateInitializationError> {
        // If RocksDB storage has data, load from it directly
        let has_data = self
            .has_leaves()
            .map_err(|e| StateInitializationError::NullifierTreeIoError(e.to_string()))?;
        if has_data {
            let smt = load_smt(self)?;
            return Ok(NullifierTree::new_unchecked(smt));
        }

        info!(target: COMPONENT, "RocksDB nullifier tree storage is empty, populating from SQLite");
        let nullifiers = db.select_all_nullifiers().await?;
        let entries = nullifiers.into_iter().map(|info| (info.nullifier, info.block_num));
        NullifierTree::with_storage_from_entries(self, entries)
            .map_err(StateInitializationError::FailedToCreateNullifierTree)
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Loads an SMT from persistent storage.
#[cfg(feature = "rocksdb")]
pub fn load_smt<S: SmtStorage>(storage: S) -> Result<LargeSmt<S>, StateInitializationError> {
    LargeSmt::new(storage).map_err(account_tree_large_smt_error_to_init_error)
}

// TREE LOADING FUNCTIONS
// ================================================================================================

/// Loads the blockchain MMR from all block headers in the database.
#[instrument(target = COMPONENT, skip_all)]
pub async fn load_mmr(db: &mut Db) -> Result<Blockchain, StateInitializationError> {
    let block_commitments: Vec<miden_protocol::Word> = db
        .select_all_block_headers()
        .await?
        .iter()
        .map(BlockHeader::commitment)
        .collect();

    // SAFETY: We assume the loaded MMR is valid and does not have more than u32::MAX
    // entries.
    let chain_mmr = Blockchain::from_mmr_unchecked(block_commitments.into());

    Ok(chain_mmr)
}

/// Loads SMT forest with storage map and vault Merkle paths for all public accounts.
#[instrument(target = COMPONENT, skip_all, fields(block_num = %block_num))]
pub async fn load_smt_forest(
    db: &mut Db,
    block_num: BlockNumber,
) -> Result<InnerForest, StateInitializationError> {
    use miden_protocol::account::delta::AccountDelta;

    let public_account_ids = db.select_all_public_account_ids().await?;

    // Acquire write lock once for the entire initialization
    let mut forest = InnerForest::new();

    // Process each account
    for account_id in public_account_ids {
        // Get the full account from the database
        let account_info = db.select_account(account_id).await?;
        let account = account_info.details.expect("public accounts always have details in DB");

        // Convert the full account to a full-state delta
        let delta =
            AccountDelta::try_from(account).expect("accounts from DB should not have seeds");

        // Use the unified update method (will recognize it's a full-state delta)
        forest.update_account(block_num, &delta)?;
    }

    Ok(forest)
}

// CONSISTENCY VERIFICATION
// ================================================================================================

/// Verifies that tree roots match the expected roots from the latest block header.
///
/// This check ensures the database and tree storage (memory or persistent) haven't diverged due to
/// corruption or incomplete shutdown. When trees are rebuilt from the database, they will naturally
/// match; when loaded from persistent storage, this catches any inconsistencies.
///
/// # Arguments
/// * `account_tree_root` - Root of the loaded account tree
/// * `nullifier_tree_root` - Root of the loaded nullifier tree
/// * `db` - Database connection to fetch the latest block header
///
/// # Errors
/// Returns `StateInitializationError::TreeStorageDiverged` if any root doesn't match.
#[instrument(target = COMPONENT, skip_all)]
pub async fn verify_tree_consistency(
    account_tree_root: Word,
    nullifier_tree_root: Word,
    db: &mut Db,
) -> Result<(), StateInitializationError> {
    // Fetch the latest block header to get the expected roots
    let latest_header = db.select_block_header_by_block_num(None).await?;

    let (block_num, expected_account_root, expected_nullifier_root) = latest_header
        .map(|header| (header.block_num(), header.account_root(), header.nullifier_root()))
        .unwrap_or_default();

    // Verify account tree root
    if account_tree_root != expected_account_root {
        return Err(StateInitializationError::TreeStorageDiverged {
            tree_name: "Account",
            block_num,
            tree_root: account_tree_root,
            block_root: expected_account_root,
        });
    }

    // Verify nullifier tree root
    if nullifier_tree_root != expected_nullifier_root {
        return Err(StateInitializationError::TreeStorageDiverged {
            tree_name: "Nullifier",
            block_num,
            tree_root: nullifier_tree_root,
            block_root: expected_nullifier_root,
        });
    }

    Ok(())
}
