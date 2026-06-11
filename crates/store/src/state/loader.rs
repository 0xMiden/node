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
use std::num::NonZeroUsize;
use std::path::Path;

use miden_crypto::merkle::mmr::Mmr;
use miden_crypto::merkle::smt::{Backend, ForestInMemoryBackend};
#[cfg(feature = "rocksdb")]
use miden_crypto::merkle::smt::{
    ForestPersistentBackend,
    PersistentBackendConfig,
    RocksDbStorage,
    SmtStorageReader,
};
#[cfg(feature = "rocksdb")]
use miden_node_utils::clap::RocksDbOptions;
use miden_protocol::account::{AccountId, AccountStorageHeader, StorageSlotType};
use miden_protocol::block::account_tree::{AccountIdKey, AccountTree};
use miden_protocol::block::nullifier_tree::NullifierTree;
use miden_protocol::block::{BlockNumber, Blockchain};
#[cfg(not(feature = "rocksdb"))]
use miden_protocol::crypto::merkle::smt::MemoryStorage;
use miden_protocol::crypto::merkle::smt::{LargeSmt, LargeSmtError, SmtStorage};
use miden_protocol::{Felt, Word};
#[cfg(feature = "rocksdb")]
use tracing::info;
use tracing::instrument;

use crate::COMPONENT;
use crate::account_state_forest::AccountStateForest;
use crate::db::Db;
use crate::db::models::queries::BlockHeaderCommitment;
use crate::errors::{DatabaseError, StateInitializationError};

// CONSTANTS
// ================================================================================================

/// Directory name for the account tree storage within the data directory.
pub const ACCOUNT_TREE_STORAGE_DIR: &str = "accounttree";

/// Directory name for the nullifier tree storage within the data directory.
pub const NULLIFIER_TREE_STORAGE_DIR: &str = "nullifiertree";

/// Directory name for the account state forest storage within the data directory.
pub const ACCOUNT_STATE_FOREST_STORAGE_DIR: &str = "accountstateforest";

/// Page size for loading account commitments from the database during tree rebuilding. This limits
/// memory usage when rebuilding trees with millions of accounts.
const ACCOUNT_COMMITMENTS_PAGE_SIZE: NonZeroUsize = NonZeroUsize::new(10_000).unwrap();

/// Page size for loading nullifiers from the database during tree rebuilding. This limits memory
/// usage when rebuilding trees with millions of nullifiers.
const NULLIFIERS_PAGE_SIZE: NonZeroUsize = NonZeroUsize::new(10_000).unwrap();

/// Page size for loading public account IDs from the database during forest rebuilding. This limits
/// memory usage when rebuilding with millions of public accounts.
const PUBLIC_ACCOUNT_IDS_PAGE_SIZE: NonZeroUsize = NonZeroUsize::new(1_000).unwrap();

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
        err @ (LargeSmtError::RootMismatch { .. } | LargeSmtError::StorageNotEmpty) => {
            StateInitializationError::AccountTreeIoError(err.as_report())
        },
    }
}

/// Converts a block number to the leaf value format used in the nullifier tree.
///
/// This matches the format used by `NullifierBlock::from(BlockNumber)::into()`,
/// which is `[Felt::from(block_num), 0, 0, 0]`.
fn block_num_to_nullifier_leaf(block_num: BlockNumber) -> Word {
    Word::from([Felt::from(block_num), Felt::ZERO, Felt::ZERO, Felt::ZERO])
}

// TREE STORAGE LOADER TRAIT
// ================================================================================================

/// Trait for loading trees from storage.
///
/// For `MemoryStorage`, the tree is rebuilt from database entries on each startup.
/// For `RocksDbStorage`, the tree is loaded directly from disk (much faster for large trees).
///
/// Missing or corrupted storage is handled by the `verify_tree_consistency` check after loading,
/// which detects divergence between persistent storage and the database. If divergence is detected,
/// the user should manually delete the tree storage directories and restart the node.
pub trait TreeStorageLoader: SmtStorage + Sized {
    /// A configuration type for the implementation.
    type Config: std::fmt::Debug + std::default::Default;
    /// Creates a storage backend for the given domain.
    fn create(
        data_dir: &Path,
        storage_options: &Self::Config,
        domain: &'static str,
    ) -> Result<Self, StateInitializationError>;

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

// ACCOUNT FOREST LOADER TRAIT
// ================================================================================================

/// Trait for loading account state forests from storage.
///
/// For `ForestInMemoryBackend`, the forest is rebuilt from database entries on each startup. For
/// `ForestPersistentBackend`, the forest is loaded directly from disk if data exists, otherwise it
/// is rebuilt from the database and persisted.
pub trait AccountForestLoader: Backend + Sized {
    /// A configuration type for the implementation.
    type Config: std::fmt::Debug + std::default::Default;

    /// Creates a forest backend for the given domain.
    fn create(
        data_dir: &Path,
        storage_options: &Self::Config,
        domain: &'static str,
    ) -> Result<Self, StateInitializationError>;

    /// Loads the account state forest, either from persistent storage or by rebuilding from DB.
    fn load_account_state_forest(
        self,
        db: &mut Db,
        block_num: BlockNumber,
    ) -> impl Future<Output = Result<AccountStateForest<Self>, StateInitializationError>> + Send;
}

// MEMORY STORAGE IMPLEMENTATION
// ================================================================================================

#[cfg(not(feature = "rocksdb"))]
impl TreeStorageLoader for MemoryStorage {
    type Config = ();
    fn create(
        _data_dir: &Path,
        _storage_options: &Self::Config,
        _domain: &'static str,
    ) -> Result<Self, StateInitializationError> {
        Ok(MemoryStorage::default())
    }

    #[instrument(target = COMPONENT, skip_all)]
    async fn load_account_tree(
        self,
        db: &mut Db,
    ) -> Result<AccountTree<LargeSmt<Self>>, StateInitializationError> {
        let mut smt = LargeSmt::with_entries(self, std::iter::empty())
            .map_err(account_tree_large_smt_error_to_init_error)?;

        // Load account commitments in pages to avoid loading millions of entries at once
        let mut cursor = None;
        loop {
            let page = db
                .select_account_commitments_paged(ACCOUNT_COMMITMENTS_PAGE_SIZE, cursor)
                .await?;

            cursor = page.next_cursor;
            if page.commitments.is_empty() {
                break;
            }

            let entries = page
                .commitments
                .into_iter()
                .map(|(id, commitment)| (AccountIdKey::from(id).as_word(), commitment));

            let mutations = smt
                .compute_mutations(entries)
                .map_err(account_tree_large_smt_error_to_init_error)?;
            smt.apply_mutations(mutations)
                .map_err(account_tree_large_smt_error_to_init_error)?;

            if cursor.is_none() {
                break;
            }
        }

        AccountTree::new(smt).map_err(StateInitializationError::FailedToCreateAccountsTree)
    }

    // TODO: Make the loading methodology for account and nullifier trees consistent. Currently we
    // use `NullifierTree::new_unchecked()` for nullifiers but `AccountTree::new()` for accounts.
    // Consider using `NullifierTree::with_storage_from_entries()` for consistency.
    #[instrument(target = COMPONENT, skip_all)]
    async fn load_nullifier_tree(
        self,
        db: &mut Db,
    ) -> Result<NullifierTree<LargeSmt<Self>>, StateInitializationError> {
        let mut smt = LargeSmt::with_entries(self, std::iter::empty())
            .map_err(account_tree_large_smt_error_to_init_error)?;

        // Load nullifiers in pages to avoid loading millions of entries at once
        let mut cursor = None;
        loop {
            let page = db.select_nullifiers_paged(NULLIFIERS_PAGE_SIZE, cursor).await?;

            cursor = page.next_cursor;
            if page.nullifiers.is_empty() {
                break;
            }

            let entries = page.nullifiers.into_iter().map(|info| {
                (info.nullifier.as_word(), block_num_to_nullifier_leaf(info.block_num))
            });

            let mutations = smt
                .compute_mutations(entries)
                .map_err(account_tree_large_smt_error_to_init_error)?;
            smt.apply_mutations(mutations)
                .map_err(account_tree_large_smt_error_to_init_error)?;

            if cursor.is_none() {
                break;
            }
        }

        Ok(NullifierTree::new_unchecked(smt))
    }
}

// ROCKSDB STORAGE IMPLEMENTATION
// ================================================================================================

#[cfg(feature = "rocksdb")]
impl TreeStorageLoader for RocksDbStorage {
    type Config = RocksDbOptions;
    fn create(
        data_dir: &Path,
        storage_options: &Self::Config,
        domain: &'static str,
    ) -> Result<Self, StateInitializationError> {
        let storage_path = data_dir.join(domain);
        let config = storage_options.with_path(&storage_path);
        fs_err::create_dir_all(&storage_path)
            .map_err(|e| StateInitializationError::AccountTreeIoError(e.to_string()))?;
        RocksDbStorage::open(config)
            .map_err(|e| StateInitializationError::AccountTreeIoError(e.to_string()))
    }

    #[instrument(target = COMPONENT, skip_all)]
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

        let mut smt = LargeSmt::with_entries(self, std::iter::empty())
            .map_err(account_tree_large_smt_error_to_init_error)?;

        // Load account commitments in pages to avoid loading millions of entries at once
        let mut cursor = None;
        loop {
            let page = db
                .select_account_commitments_paged(ACCOUNT_COMMITMENTS_PAGE_SIZE, cursor)
                .await?;

            cursor = page.next_cursor;
            if page.commitments.is_empty() {
                break;
            }

            let entries = page
                .commitments
                .into_iter()
                .map(|(id, commitment)| (AccountIdKey::from(id).as_word(), commitment));

            let mutations = smt
                .compute_mutations(entries)
                .map_err(account_tree_large_smt_error_to_init_error)?;
            smt.apply_mutations(mutations)
                .map_err(account_tree_large_smt_error_to_init_error)?;

            if cursor.is_none() {
                break;
            }
        }

        AccountTree::new(smt).map_err(StateInitializationError::FailedToCreateAccountsTree)
    }

    #[instrument(target = COMPONENT, skip_all)]
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

        let mut smt = LargeSmt::with_entries(self, std::iter::empty())
            .map_err(account_tree_large_smt_error_to_init_error)?;

        // Load nullifiers in pages to avoid loading millions of entries at once
        let mut cursor = None;
        loop {
            let page = db.select_nullifiers_paged(NULLIFIERS_PAGE_SIZE, cursor).await?;

            cursor = page.next_cursor;
            if page.nullifiers.is_empty() {
                break;
            }

            let entries = page.nullifiers.into_iter().map(|info| {
                (info.nullifier.as_word(), block_num_to_nullifier_leaf(info.block_num))
            });

            let mutations = smt
                .compute_mutations(entries)
                .map_err(account_tree_large_smt_error_to_init_error)?;
            smt.apply_mutations(mutations)
                .map_err(account_tree_large_smt_error_to_init_error)?;

            if cursor.is_none() {
                break;
            }
        }

        Ok(NullifierTree::new_unchecked(smt))
    }
}

// ACCOUNT FOREST BACKEND IMPLEMENTATIONS
// ================================================================================================

impl AccountForestLoader for ForestInMemoryBackend {
    type Config = ();

    fn create(
        _data_dir: &Path,
        _storage_options: &Self::Config,
        _domain: &'static str,
    ) -> Result<Self, StateInitializationError> {
        Ok(ForestInMemoryBackend::new())
    }

    #[instrument(target = COMPONENT, skip_all, fields(block.number = %block_num))]
    async fn load_account_state_forest(
        self,
        db: &mut Db,
        block_num: BlockNumber,
    ) -> Result<AccountStateForest<Self>, StateInitializationError> {
        let mut forest = AccountStateForest::from_backend(self)
            .map_err(|e| StateInitializationError::AccountStateForestIoError(e.to_string()))?;
        rebuild_account_state_forest(&mut forest, db, block_num).await?;
        Ok(forest)
    }
}

#[cfg(feature = "rocksdb")]
impl AccountForestLoader for ForestPersistentBackend {
    type Config = RocksDbOptions;

    fn create(
        data_dir: &Path,
        storage_options: &Self::Config,
        domain: &'static str,
    ) -> Result<Self, StateInitializationError> {
        let storage_path = data_dir.join(domain);
        fs_err::create_dir_all(&storage_path)
            .map_err(|e| StateInitializationError::AccountStateForestIoError(e.to_string()))?;

        let max_open_files = usize::try_from(storage_options.max_open_fds).map_err(|_| {
            StateInitializationError::AccountStateForestIoError(format!(
                "invalid account state forest RocksDB max_open_fds: {}",
                storage_options.max_open_fds
            ))
        })?;
        let config = PersistentBackendConfig::new(&storage_path)
            .map_err(|e| StateInitializationError::AccountStateForestIoError(e.to_string()))?
            .with_cache_size_bytes(storage_options.cache_size_in_bytes)
            .with_max_open_files(max_open_files);

        ForestPersistentBackend::load(config)
            .map_err(|e| StateInitializationError::AccountStateForestIoError(e.to_string()))
    }

    #[instrument(target = COMPONENT, skip_all, fields(block.number = %block_num))]
    async fn load_account_state_forest(
        self,
        db: &mut Db,
        block_num: BlockNumber,
    ) -> Result<AccountStateForest<Self>, StateInitializationError> {
        let mut forest = AccountStateForest::from_backend(self)
            .map_err(|e| StateInitializationError::AccountStateForestIoError(e.to_string()))?;

        if forest.lineage_count() != 0 {
            return Ok(forest);
        }

        info!(
            target: COMPONENT,
            "RocksDB account state forest storage is empty, populating from SQLite"
        );
        rebuild_account_state_forest(&mut forest, db, block_num).await?;
        Ok(forest)
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Loads an SMT from persistent storage.
#[cfg(feature = "rocksdb")]
pub fn load_smt<S: SmtStorage>(storage: S) -> Result<LargeSmt<S>, StateInitializationError> {
    LargeSmt::load(storage).map_err(account_tree_large_smt_error_to_init_error)
}

// TREE LOADING FUNCTIONS
// ================================================================================================

/// Loads the blockchain MMR from all block headers in the database.
#[instrument(target = COMPONENT, skip_all)]
pub async fn load_mmr(db: &mut Db) -> Result<Blockchain, StateInitializationError> {
    let block_commitments = db.select_all_block_header_commitments().await?;

    // SAFETY: We assume the loaded MMR is valid and does not have more than u32::MAX entries.
    let mmr = Mmr::try_from_iter(block_commitments.into_iter().map(BlockHeaderCommitment::word))
        .expect("loaded MMR exceeds maximum allowed size");
    let chain_mmr = Blockchain::from_mmr_unchecked(mmr);

    Ok(chain_mmr)
}

/// Rebuilds SMT forest with storage map and vault Merkle paths for all public accounts.
#[instrument(target = COMPONENT, skip_all, fields(block.number = %block_num))]
pub async fn rebuild_account_state_forest(
    forest: &mut AccountStateForest<impl Backend>,
    db: &mut Db,
    block_num: BlockNumber,
) -> Result<(), StateInitializationError> {
    use miden_protocol::account::delta::AccountDelta;

    let mut cursor = None;

    loop {
        let page = db.select_public_account_ids_paged(PUBLIC_ACCOUNT_IDS_PAGE_SIZE, cursor).await?;

        if page.account_ids.is_empty() {
            break;
        }

        // Process each account in this page
        for account_id in page.account_ids {
            // TODO: Loading the full account from the database is inefficient and will need to go
            // away. <https://github.com/0xMiden/node/issues/1556>
            let account_info = db.select_account(account_id).await?;
            let account = account_info
                .details
                .ok_or(StateInitializationError::PublicAccountMissingDetails(account_id))?;

            // Convert the full account to a full-state delta
            let delta = AccountDelta::try_from(account).map_err(|e| {
                StateInitializationError::AccountToDeltaConversionFailed(e.to_string())
            })?;

            forest.update_account(block_num, &delta)?;
        }

        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }

    Ok(())
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

/// Verifies that the account state forest matches latest public account roots from SQLite.
///
/// This check ensures persisted account state forest has not diverged from the latest
/// account states in SQLite. When the forest is rebuilt from SQLite, it will naturally
/// match; when loaded from `RocksDB`, this catches corruption or incomplete shutdown.
#[instrument(target = COMPONENT, skip_all)]
pub async fn verify_account_state_forest_consistency(
    forest: &AccountStateForest<impl Backend>,
    db: &mut Db,
) -> Result<(), StateInitializationError> {
    let mut cursor = None;

    loop {
        let page = db
            .select_public_account_state_roots_paged(PUBLIC_ACCOUNT_IDS_PAGE_SIZE, cursor)
            .await?;

        if page.accounts.is_empty() {
            break;
        }

        for account in page.accounts {
            verify_account_state_forest_record(
                forest,
                account.account_id,
                account.vault_root,
                &account.storage_header,
            )?;
        }

        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }

    Ok(())
}

fn verify_account_state_forest_record(
    forest: &AccountStateForest<impl Backend>,
    account_id: AccountId,
    vault_root: Word,
    storage_header: &AccountStorageHeader,
) -> Result<(), StateInitializationError> {
    let forest_vault_root = forest.get_latest_vault_root(account_id);
    if forest_vault_root != vault_root {
        return Err(StateInitializationError::AccountStateForestStorageDiverged {
            account_id,
            slot_name: None,
            forest_root: forest_vault_root,
            database_root: vault_root,
        });
    }

    for slot in storage_header.slots() {
        if slot.slot_type() != StorageSlotType::Map {
            continue;
        }

        let forest_root = forest.get_latest_storage_map_root(account_id, slot.name());
        let database_root = slot.value();
        if forest_root != database_root {
            return Err(StateInitializationError::AccountStateForestStorageDiverged {
                account_id,
                slot_name: Some(slot.name().to_string()),
                forest_root,
                database_root,
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use miden_protocol::account::{
        AccountId,
        AccountStorageHeader,
        StorageSlotHeader,
        StorageSlotName,
        StorageSlotType,
    };
    use miden_protocol::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE;

    use super::*;

    #[test]
    fn account_state_forest_consistency_detects_storage_map_root_mismatch() {
        let account_id = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE)
            .expect("test account ID should be valid");
        let slot_name =
            StorageSlotName::new("account::balances").expect("slot name should be valid");
        let expected_storage_root = Word::from([1, 0, 0, 0u32]);
        let storage_header = AccountStorageHeader::new(vec![StorageSlotHeader::new(
            slot_name.clone(),
            StorageSlotType::Map,
            expected_storage_root,
        )])
        .expect("storage header should be valid");
        let forest = AccountStateForest::new();

        let error = verify_account_state_forest_record(
            &forest,
            account_id,
            AccountStateForest::empty_smt_root(),
            &storage_header,
        )
        .expect_err("storage map root mismatch should be detected");

        assert_matches::assert_matches!(
            error,
            StateInitializationError::AccountStateForestStorageDiverged {
                account_id: actual_account_id,
                slot_name: Some(actual_slot_name),
                forest_root,
                database_root,
            } if actual_account_id == account_id
                && actual_slot_name == slot_name.to_string()
                && forest_root == AccountStateForest::empty_smt_root()
                && database_root == expected_storage_root
        );
    }

    #[test]
    fn account_state_forest_consistency_detects_vault_root_mismatch() {
        let account_id = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE)
            .expect("test account ID should be valid");
        let expected_vault_root = Word::from([2, 0, 0, 0u32]);
        let storage_header =
            AccountStorageHeader::new(Vec::new()).expect("storage header should be valid");
        let forest = AccountStateForest::new();

        let error = verify_account_state_forest_record(
            &forest,
            account_id,
            expected_vault_root,
            &storage_header,
        )
        .expect_err("vault root mismatch should be detected");

        assert_matches::assert_matches!(
            error,
            StateInitializationError::AccountStateForestStorageDiverged {
                account_id: actual_account_id,
                slot_name: None,
                forest_root,
                database_root,
            } if actual_account_id == account_id
                && forest_root == AccountStateForest::empty_smt_root()
                && database_root == expected_vault_root
        );
    }
}
