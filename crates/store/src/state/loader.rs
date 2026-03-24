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
#[cfg(feature = "rocksdb")]
use miden_large_smt_backend_rocksdb::RocksDbStorage;
use miden_node_utils::clap::RocksDbOptions;
use miden_protocol::block::account_tree::{AccountTree, account_id_to_smt_key};
use miden_protocol::block::nullifier_tree::NullifierTree;
use miden_protocol::block::{BlockNumber, Blockchain};
#[cfg(not(feature = "rocksdb"))]
use miden_protocol::crypto::merkle::smt::MemoryStorage;
use miden_protocol::crypto::merkle::smt::{LargeSmt, LargeSmtError, SmtStorage};
use miden_protocol::{Felt, FieldElement, Word};
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

/// Page size for loading account commitments from the database during tree rebuilding.
/// This limits memory usage when rebuilding trees with millions of accounts.
const ACCOUNT_COMMITMENTS_PAGE_SIZE: NonZeroUsize = NonZeroUsize::new(10_000).unwrap();

/// Page size for loading nullifiers from the database during tree rebuilding.
/// This limits memory usage when rebuilding trees with millions of nullifiers.
const NULLIFIERS_PAGE_SIZE: NonZeroUsize = NonZeroUsize::new(10_000).unwrap();

/// Page size for loading public account IDs from the database during forest rebuilding.
/// This limits memory usage when rebuilding with millions of public accounts.
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
    }
}

/// Converts a block number to the leaf value format used in the nullifier tree.
///
/// This matches the format used by `NullifierBlock::from(BlockNumber)::into()`,
/// which is `[Felt::from(block_num), 0, 0, 0]`.
fn block_num_to_nullifier_leaf(block_num: BlockNumber) -> Word {
    Word::from([Felt::from(block_num), Felt::ZERO, Felt::ZERO, Felt::ZERO])
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

// MEMORY STORAGE IMPLEMENTATION
// ================================================================================================

#[cfg(not(feature = "rocksdb"))]
impl StorageLoader for MemoryStorage {
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
                .map(|(id, commitment)| (account_id_to_smt_key(id), commitment));

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

    // TODO: Make the loading methodology for account and nullifier trees consistent.
    // Currently we use `NullifierTree::new_unchecked()` for nullifiers but `AccountTree::new()`
    // for accounts. Consider using `NullifierTree::with_storage_from_entries()` for consistency.
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
impl StorageLoader for RocksDbStorage {
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
                .map(|(id, commitment)| (account_id_to_smt_key(id), commitment));

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
    let block_commitments = db.select_all_block_header_commitments().await?;

    // SAFETY: We assume the loaded MMR is valid and does not have more than u32::MAX
    // entries.
    let chain_mmr = Blockchain::from_mmr_unchecked(Mmr::from(
        block_commitments.iter().copied().map(BlockHeaderCommitment::word),
    ));

    Ok(chain_mmr)
}

/// Loads SMT forest with storage map and vault Merkle paths for all public accounts.
#[instrument(target = COMPONENT, skip_all, fields(block.number = %block_num))]
pub async fn load_smt_forest(
    db: &Db,
    block_num: BlockNumber,
) -> Result<AccountStateForest, StateInitializationError> {
    use futures::StreamExt;
    use indicatif::{MultiProgress, ProgressBar, ProgressStyle};

    // How many DB fetches to drive concurrently.
    const CONCURRENCY: usize = 64;

    let total = db.count_accounts().await? as u64;

    let multi = MultiProgress::new();
    let style =
        ProgressStyle::with_template("{msg:12} [{bar:50.cyan/blue}] {pos}/{len} ({eta} remaining)")
            .unwrap()
            .progress_chars("=> ");

    let pb_page = multi.add(ProgressBar::new(total));
    pb_page.set_style(style.clone());
    pb_page.set_message("paging");

    let pb_fetch = multi.add(ProgressBar::new(total));
    pb_fetch.set_style(style.clone());
    pb_fetch.set_message("fetching");

    let pb_insert = multi.add(ProgressBar::new(total));
    pb_insert.set_style(style);
    pb_insert.set_message("inserting");

    // Build a stream of (account_id, assets, map_entries) by paging through IDs and
    // mapping each one to a fetch future, then running up to CONCURRENCY futures at once.
    // Each item in the stream is a full page of account IDs.
    let page_stream = async_stream::stream! {
        let mut cursor = None;
        loop {
            let page = db
                .select_public_account_ids_paged(PUBLIC_ACCOUNT_IDS_PAGE_SIZE, cursor)
                .await?;
            let done = page.next_cursor.is_none();
            let n = page.account_ids.len() as u64;
            yield Ok::<_, StateInitializationError>(page.account_ids);
            pb_page.inc(n);
            if done {
                break;
            }
            cursor = page.next_cursor;
        }
        pb_page.finish_with_message("paged");
    };

    // Map each page to a single batch fetch future.
    let fetch_stream = page_stream.map(|res| {
        let pb_fetch = pb_fetch.clone();
        async move {
            let account_ids = res?;
            let n = account_ids.len() as u64;
            let batch = db.select_account_forest_data_batch(account_ids).await?;
            pb_fetch.inc(n);
            Ok::<_, StateInitializationError>(batch)
        }
    });

    let buffered = fetch_stream.buffered(CONCURRENCY);

    let mut forest = AccountStateForest::new();
    tokio::pin!(buffered);
    while let Some(result) = buffered.next().await {
        let batch = result?;
        let n = batch.len() as u64;
        forest.insert_accounts_batch(block_num, batch)?;
        pb_insert.inc(n);
    }
    pb_fetch.finish_with_message("fetched");
    pb_insert.finish_with_message("inserted");

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
