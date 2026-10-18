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
use miden_node_tracing::{info, miden_instrument, warn};
#[cfg(feature = "rocksdb")]
use miden_node_utils::clap::RocksDbOptions;
use miden_protocol::account::{AccountId, AccountStorageHeader, StorageSlotType};
use miden_protocol::block::account_tree::{AccountIdKey, AccountTree};
use miden_protocol::block::nullifier_tree::NullifierTree;
use miden_protocol::block::{BlockHeader, BlockNumber, Blockchain};
#[cfg(not(feature = "rocksdb"))]
use miden_protocol::crypto::merkle::smt::MemoryStorage;
use miden_protocol::crypto::merkle::smt::{LargeSmt, LargeSmtError, SmtStorage};
use miden_protocol::{Felt, Word};

use crate::account_state_forest::AccountStateForest;
use crate::db::{BlockHeaderCommitment, Db};
use crate::errors::{DatabaseError, StateInitializationError};
use crate::state::chain_mmr_checkpoint::ChainMmrCheckpoint;
use crate::{COMPONENT, LOG_TARGET};

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

/// The read-only snapshot storage backend for trees, used by in-memory state snapshots.
pub type TreeStorageReader = <TreeStorage as SmtStorage>::Reader;

// ERROR CONVERSION
// ================================================================================================

/// Converts a `LargeSmtError` into a `StateInitializationError`.
pub fn account_tree_large_smt_error_to_init_error(e: LargeSmtError) -> StateInitializationError {
    use miden_node_tracing::ErrorReport;
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
        db: &Db,
    ) -> impl Future<Output = Result<AccountTree<LargeSmt<Self>>, StateInitializationError>> + Send;

    /// Loads a nullifier tree, either from persistent storage or by rebuilding from DB.
    fn load_nullifier_tree(
        self,
        db: &Db,
    ) -> impl Future<Output = Result<NullifierTree<LargeSmt<Self>>, StateInitializationError>> + Send;
}

// ACCOUNT FOREST LOADER TRAIT
// ================================================================================================

/// Trait for loading account state forests from storage.
///
/// For `ForestInMemoryBackend`, the forest is rebuilt from database entries on each startup. For
/// `ForestPersistentBackend`, the forest is loaded directly from disk if data exists, otherwise it
/// is rebuilt from the database and persisted.
pub(crate) trait AccountForestLoader: Backend + Sized {
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
        db: &Db,
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

    #[miden_instrument(
        target = COMPONENT,
    )]
    async fn load_account_tree(
        self,
        db: &Db,
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
    #[miden_instrument(
        target = COMPONENT,
    )]
    async fn load_nullifier_tree(
        self,
        db: &Db,
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
    // Opening RocksDB replays unflushed WAL segments and fills the table cache, which can take
    // seconds; the span makes this cost visible in startup traces.
    #[miden_instrument(
        target = COMPONENT,
        name = "open_tree_storage",
        fields(path = domain),
    )]
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

    #[miden_instrument(
        target = COMPONENT,
    )]
    async fn load_account_tree(
        self,
        db: &Db,
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

        info!(target: LOG_TARGET, "RocksDB account tree storage is empty, populating from SQLite");

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

    #[miden_instrument(
        target = COMPONENT,
    )]
    async fn load_nullifier_tree(
        self,
        db: &Db,
    ) -> Result<NullifierTree<LargeSmt<Self>>, StateInitializationError> {
        // If RocksDB storage has data, load from it directly

        let has_data = self
            .has_leaves()
            .map_err(|e| StateInitializationError::NullifierTreeIoError(e.to_string()))?;
        if has_data {
            let smt = load_smt(self)?;
            return Ok(NullifierTree::new_unchecked(smt));
        }

        info!(target: LOG_TARGET, "RocksDB nullifier tree storage is empty, populating from SQLite");

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

    #[miden_instrument(
        target = COMPONENT,
        fields(
            block.number = block_num,
        ),
    )]
    async fn load_account_state_forest(
        self,
        db: &Db,
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

    // Opening RocksDB replays unflushed WAL segments and fills the table cache, which can take
    // seconds; the span makes this cost visible in startup traces.
    #[miden_instrument(
        target = COMPONENT,
        name = "open_forest_storage",
        fields(path = domain),
    )]
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

    #[miden_instrument(
        target = COMPONENT,
        fields(
            block.number = block_num,
        ),
    )]
    async fn load_account_state_forest(
        self,
        db: &Db,
        block_num: BlockNumber,
    ) -> Result<AccountStateForest<Self>, StateInitializationError> {
        let mut forest = AccountStateForest::from_backend(self)
            .map_err(|e| StateInitializationError::AccountStateForestIoError(e.to_string()))?;

        if forest.lineage_count() != 0 {
            return Ok(forest);
        }

        info!(
            target: LOG_TARGET,
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

/// Loads the blockchain MMR, either by restoring the on-disk checkpoint or by rebuilding from all
/// block headers in the database.
///
/// The checkpoint is a cache of the derived MMR structure; the MMR is append-only, so a stale
/// checkpoint is a valid prefix and is topped up with the block commitments it is missing. A
/// missing, corrupt, or divergent checkpoint falls back to a full rebuild. Either path is verified
/// against the latest block header, and the topped-up blocks are appended to the
/// checkpoint whenever it was behind the database.
#[miden_instrument(
    target = COMPONENT,
)]
pub async fn load_mmr(
    db: &Db,
    checkpoint: &ChainMmrCheckpoint,
) -> Result<Blockchain, StateInitializationError> {
    let latest_header = db.select_block_header_by_block_num(None).await?;

    // Fast path: restore the checkpoint and top it up. Falls through to a full rebuild if there is
    // no usable checkpoint, or if the topped-up result doesn't match the database.
    if let Some(chain_mmr) =
        try_restore_mmr_from_checkpoint(db, checkpoint, latest_header.as_ref()).await?
    {
        return Ok(chain_mmr);
    }

    rebuild_mmr_from_database(db, checkpoint, latest_header.as_ref()).await
}

/// Attempts to restore the chain MMR from the on-disk checkpoint.
///
/// Returns `Ok(None)` — never an error — when the checkpoint can't be used, so the caller falls
/// back to a full rebuild:
/// - there is no genesis block yet (nothing to restore against);
/// - the checkpoint file is missing, unreadable, or holds no usable prefix (see
///   [`ChainMmrCheckpoint::read`]);
/// - the checkpoint, topped up with the blocks committed since it was taken, does not match the
///   latest block header (e.g. the file diverged from the database).
async fn try_restore_mmr_from_checkpoint(
    db: &Db,
    checkpoint: &ChainMmrCheckpoint,
    latest_header: Option<&BlockHeader>,
) -> Result<Option<Blockchain>, StateInitializationError> {
    let Some(header) = latest_header else {
        return Ok(None);
    };

    let chain_length = header.block_num().as_u32() + 1;
    let Some(mut chain_mmr) = checkpoint.read(chain_length) else {
        return Ok(None);
    };

    // The MMR is append-only, so the checkpoint is a valid prefix of the chain; append the
    // commitments for the blocks committed after it was taken.
    let checkpoint_blocks = chain_mmr.num_blocks();
    let missing_commitments = db
        .select_block_header_commitments_from(BlockNumber::from(checkpoint_blocks))
        .await?;
    for commitment in missing_commitments {
        chain_mmr.push(commitment.word());
    }

    if let Err(err) = verify_chain_mmr_consistency(&chain_mmr, Some(header)) {
        warn!(
            &err,
            target: LOG_TARGET,
            "Chain MMR checkpoint diverged from the database; rebuilding"
        );
        return Ok(None);
    }

    info!(
        target: LOG_TARGET,
        "Loaded chain MMR from checkpoint",
        chain_mmr.blocks.checkpointed = checkpoint_blocks,
        chain_mmr.blocks.appended = chain_length - checkpoint_blocks
    );

    // Keep the on-disk checkpoint caught up so the next startup has fewer blocks to append. Startup
    // is off the block-apply path, so a file the append cannot extend (e.g. one whose torn tail
    // `read` skipped over) is healed here with a full rewrite.
    if !checkpoint.append(&chain_mmr, checkpoint_blocks) {
        checkpoint.write(&chain_mmr);
    }

    Ok(Some(chain_mmr))
}

/// Rebuilds the chain MMR from every block header commitment in the database, then writes it to the
/// checkpoint so the next startup can restore it instead of rebuilding.
async fn rebuild_mmr_from_database(
    db: &Db,
    checkpoint: &ChainMmrCheckpoint,
    latest_header: Option<&BlockHeader>,
) -> Result<Blockchain, StateInitializationError> {
    let block_commitments = db.select_all_block_header_commitments().await?;

    // SAFETY: We assume the loaded MMR is valid and does not have more than u32::MAX entries.
    let mmr = Mmr::try_from_iter(block_commitments.into_iter().map(BlockHeaderCommitment::word))
        .expect("loaded MMR exceeds maximum allowed size");
    let chain_mmr = Blockchain::from_mmr_unchecked(mmr);

    verify_chain_mmr_consistency(&chain_mmr, latest_header)?;

    checkpoint.write(&chain_mmr);

    Ok(chain_mmr)
}

/// Verifies that the chain MMR matches the latest block header: its peaks before the latest block
/// must hash to the header's chain commitment, and its latest leaf must be the header's commitment.
///
/// The header's chain commitment covers every block except the latest one, so the leaf check is
/// what pins down the latest block. Without it, a restored checkpoint could carry a divergent
/// latest block undetected, which would make every subsequent block fail its chain commitment check.
fn verify_chain_mmr_consistency(
    chain_mmr: &Blockchain,
    latest_header: Option<&BlockHeader>,
) -> Result<(), StateInitializationError> {
    let Some(latest_header) = latest_header else {
        return Err(StateInitializationError::GenesisBlockMissing);
    };

    let block_num = latest_header.block_num();
    let chain_mmr_leaf = chain_mmr
        .as_mmr()
        .get(block_num.as_usize())
        .map_err(|source| StateInitializationError::ChainMmrLoadError { block_num, source })?;
    if chain_mmr_leaf != latest_header.commitment() {
        return Err(StateInitializationError::ChainMmrTipDiverged {
            block_num,
            chain_mmr_leaf,
            block_header_commitment: latest_header.commitment(),
        });
    }

    let expected_chain_commitment = latest_header.chain_commitment();
    let actual_chain_commitment = chain_mmr
        .peaks_at(block_num)
        .map_err(|source| StateInitializationError::ChainMmrLoadError { block_num, source })?
        .hash_peaks();

    if actual_chain_commitment != expected_chain_commitment {
        return Err(StateInitializationError::ChainMmrStorageDiverged {
            block_num,
            chain_mmr_commitment: actual_chain_commitment,
            block_header_commitment: expected_chain_commitment,
        });
    }

    Ok(())
}

/// Rebuilds SMT forest with storage map and vault Merkle paths for all public accounts.
#[miden_instrument(
    target = COMPONENT,
    fields(
        block.number = block_num,
    ),
)]
pub async fn rebuild_account_state_forest(
    forest: &mut AccountStateForest<impl Backend>,
    db: &Db,
    block_num: BlockNumber,
) -> Result<(), StateInitializationError> {
    use miden_protocol::account::AccountPatch;

    let mut cursor = None;

    loop {
        let page = db.select_public_account_ids_paged(PUBLIC_ACCOUNT_IDS_PAGE_SIZE, cursor).await?;

        if page.account_ids.is_empty() {
            break;
        }

        let mut patches = Vec::with_capacity(page.account_ids.len());
        for account_id in page.account_ids {
            // TODO: Loading the full account from the database is inefficient and will need to go
            // away. <https://github.com/0xMiden/node/issues/1556>
            let account_info = db.select_account(account_id).await?;
            let account = account_info
                .details
                .ok_or(StateInitializationError::PublicAccountMissingDetails(account_id))?;

            // Convert the full account to a full-state patch
            let patch = AccountPatch::try_from(account).map_err(|e| {
                StateInitializationError::AccountToDeltaConversionFailed(e.to_string())
            })?;

            patches.push(patch);
        }

        forest
            .apply_rebuild_updates(block_num, patches)
            .map_err(StateInitializationError::AccountStateForestRebuild)?;

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
#[miden_instrument(
    target = COMPONENT,
)]
pub async fn verify_tree_consistency(
    account_tree_root: Word,
    nullifier_tree_root: Word,
    db: &Db,
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
#[miden_instrument(
    target = COMPONENT,
)]
pub async fn verify_account_state_forest_consistency(
    forest: &AccountStateForest<impl Backend + Sync>,
    db: &Db,
) -> Result<(), StateInitializationError> {
    use rayon::iter::{IntoParallelIterator, ParallelIterator};

    let mut cursor = None;

    loop {
        let page = db
            .select_public_account_state_roots_paged(PUBLIC_ACCOUNT_IDS_PAGE_SIZE, cursor)
            .await?;

        if page.accounts.is_empty() {
            break;
        }

        // Per-account checks are independent, so verify each page in parallel.
        page.accounts.into_par_iter().try_for_each(|account| {
            verify_account_state_forest_record(
                forest,
                account.account_id,
                account.vault_root,
                &account.storage_header,
            )
        })?;

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
    use miden_protocol::block::BlockHeader;
    use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey;
    use miden_protocol::crypto::merkle::mmr::Mmr;
    use miden_protocol::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE;

    use super::*;

    fn build_headers(count: u32) -> Vec<BlockHeader> {
        let mut mmr = Mmr::new();
        let mut headers = Vec::new();

        for block_num in 0..count {
            let chain_commitment = mmr.peaks().hash_peaks();
            let header = BlockHeader::mock(block_num, Some(chain_commitment), None, &[]);
            mmr.add(header.commitment()).expect("test MMR should accept block commitment");
            headers.push(header);
        }

        headers
    }

    #[test]
    fn chain_mmr_consistency_accepts_valid_loaded_chain() {
        let headers = build_headers(5);
        let mmr = Mmr::try_from_iter(headers.iter().map(BlockHeader::commitment))
            .expect("test MMR should build");
        let blockchain = Blockchain::from_mmr_unchecked(mmr);

        verify_chain_mmr_consistency(&blockchain, headers.last())
            .expect("valid loaded chain MMR should match latest header chain commitment");
    }

    #[test]
    fn chain_mmr_consistency_rejects_corrupted_loaded_chain() {
        let headers = build_headers(5);
        let mut commitments = headers.iter().map(BlockHeader::commitment).collect::<Vec<_>>();
        commitments[2] = Word::from([42, 0, 0, 0u32]);

        let mmr = Mmr::try_from_iter(commitments).expect("test MMR should build");
        let blockchain = Blockchain::from_mmr_unchecked(mmr);

        let error = verify_chain_mmr_consistency(&blockchain, headers.last())
            .expect_err("corrupted chain MMR should be rejected");

        assert_matches::assert_matches!(
            error,
            StateInitializationError::ChainMmrStorageDiverged {
                block_num,
                chain_mmr_commitment,
                block_header_commitment,
            } if block_num == headers.last().unwrap().block_num()
                && chain_mmr_commitment != block_header_commitment
                && block_header_commitment == headers.last().unwrap().chain_commitment()
        );
    }

    #[tokio::test]
    #[miden_node_test_macro::enable_logging]
    async fn load_mmr_rejects_chain_mmr_mismatch_from_database() {
        let temp_dir = tempfile::tempdir().expect("temp directory should be created");
        let db_path = temp_dir.path().join("store.sqlite");
        crate::db::bootstrap_database(&db_path).expect("test database should bootstrap");

        let headers = build_headers(5);
        let signing_key = SigningKey::new();
        let db = crate::db::Db::load(db_path).await.expect("test database should load");

        db.writer()
            .write::<_, DatabaseError, _>("insert corrupted block headers", move |tx| {
                for header in &headers {
                    let signatures = miden_protocol::block::BlockSignatures::new(vec![
                        signing_key.sign(header.commitment()),
                    ])
                    .expect("one signature is within bounds");
                    crate::db::queries::insert_block_header(tx, header, &signatures)?;
                }

                // Corrupt the stored commitment of one header so it disagrees with the header it
                // was stored alongside.
                tx.execute(
                    "UPDATE block_headers SET commitment = ?1 WHERE block_num = ?2",
                    &[&Word::from([42, 0, 0, 0u32]), &BlockNumber::from(2)],
                )?;

                Ok(())
            })
            .await
            .expect("test block headers should be inserted");

        let error = load_mmr(&db, &ChainMmrCheckpoint::new(temp_dir.path()))
            .await
            .expect_err("startup MMR load should reject inconsistent block headers");

        assert_matches::assert_matches!(
            error,
            StateInitializationError::ChainMmrStorageDiverged { .. }
        );
    }

    /// Bootstraps a test database at `db_path` and inserts `count` consistent block headers.
    async fn seed_headers(db_path: &Path, count: u32) -> (Vec<BlockHeader>, crate::db::Db) {
        crate::db::bootstrap_database(db_path).expect("test database should bootstrap");
        let headers = build_headers(count);
        let db = crate::db::Db::load(db_path.to_path_buf())
            .await
            .expect("test database should load");

        let headers_to_insert = headers.clone();
        let signing_key = SigningKey::new();
        db.writer()
            .write::<_, DatabaseError, _>("insert block headers", move |tx| {
                for header in &headers_to_insert {
                    let signatures = miden_protocol::block::BlockSignatures::new(vec![
                        signing_key.sign(header.commitment()),
                    ])
                    .expect("one signature is within bounds");
                    crate::db::queries::insert_block_header(tx, header, &signatures)?;
                }
                Ok(())
            })
            .await
            .expect("test block headers should be inserted");

        (headers, db)
    }

    #[tokio::test]
    #[miden_node_test_macro::enable_logging]
    async fn load_mmr_writes_and_restores_checkpoint() {
        let temp_dir = tempfile::tempdir().expect("temp directory should be created");
        let (_headers, db) = seed_headers(&temp_dir.path().join("store.sqlite"), 5).await;
        let checkpoint = ChainMmrCheckpoint::new(temp_dir.path());

        // The first load rebuilds from the database and writes the checkpoint.
        let rebuilt = load_mmr(&db, &checkpoint).await.expect("MMR should rebuild from database");
        let written = checkpoint.read(5).expect("checkpoint should have been written");
        assert_eq!(written.num_blocks(), 5);
        assert_eq!(written.commitment(), rebuilt.commitment());

        // The second load restores the checkpoint and yields the same chain.
        let restored =
            load_mmr(&db, &checkpoint).await.expect("MMR should restore from checkpoint");
        assert_eq!(restored.commitment(), rebuilt.commitment());
    }

    #[tokio::test]
    #[miden_node_test_macro::enable_logging]
    async fn load_mmr_tops_up_stale_checkpoint() {
        let temp_dir = tempfile::tempdir().expect("temp directory should be created");
        let (headers, db) = seed_headers(&temp_dir.path().join("store.sqlite"), 5).await;
        let checkpoint = ChainMmrCheckpoint::new(temp_dir.path());

        // Checkpoint the chain as of block 2; the database is 2 blocks ahead.
        let stale_mmr = Mmr::try_from_iter(headers[..3].iter().map(BlockHeader::commitment))
            .expect("test MMR should build");
        checkpoint.write(&Blockchain::from_mmr_unchecked(stale_mmr));

        let chain = load_mmr(&db, &checkpoint).await.expect("stale checkpoint should be topped up");
        assert_eq!(chain.num_blocks(), 5);

        // The topped-up chain replaces the stale checkpoint.
        let refreshed = checkpoint.read(5).expect("refreshed checkpoint should exist");
        assert_eq!(refreshed.num_blocks(), 5);
        assert_eq!(refreshed.commitment(), chain.commitment());
    }

    #[tokio::test]
    #[miden_node_test_macro::enable_logging]
    async fn load_mmr_recovers_from_corrupt_checkpoint() {
        use crate::state::chain_mmr_checkpoint::CHAIN_MMR_CHECKPOINT_FILENAME;

        let temp_dir = tempfile::tempdir().expect("temp directory should be created");
        let (_headers, db) = seed_headers(&temp_dir.path().join("store.sqlite"), 5).await;
        let checkpoint = ChainMmrCheckpoint::new(temp_dir.path());

        fs_err::write(temp_dir.path().join(CHAIN_MMR_CHECKPOINT_FILENAME), b"garbage")
            .expect("corrupt checkpoint should be written");

        let chain = load_mmr(&db, &checkpoint)
            .await
            .expect("corrupt checkpoint should fall back to a database rebuild");
        assert_eq!(chain.num_blocks(), 5);
    }

    #[tokio::test]
    #[miden_node_test_macro::enable_logging]
    async fn load_mmr_rejects_checkpoint_with_divergent_tip() {
        // A checkpoint whose latest block differs from the database, e.g. one left behind by a
        // previous network after re-bootstrapping the data directory. A genesis-only chain is the
        // extreme case, where the checkpoint holds nothing but the divergent block.
        for count in [1, 5] {
            let temp_dir = tempfile::tempdir().expect("temp directory should be created");
            let (headers, db) = seed_headers(&temp_dir.path().join("store.sqlite"), count).await;
            let checkpoint = ChainMmrCheckpoint::new(temp_dir.path());

            let mut commitments = headers.iter().map(BlockHeader::commitment).collect::<Vec<_>>();
            *commitments.last_mut().unwrap() = Word::from([42, 0, 0, 0u32]);
            let divergent_mmr = Mmr::try_from_iter(commitments).expect("test MMR should build");
            checkpoint.write(&Blockchain::from_mmr_unchecked(divergent_mmr));

            let chain = load_mmr(&db, &checkpoint)
                .await
                .expect("divergent checkpoint should fall back to a database rebuild");

            let expected = Mmr::try_from_iter(headers.iter().map(BlockHeader::commitment))
                .expect("test MMR should build");
            assert_eq!(chain.commitment(), expected.peaks().hash_peaks());
        }
    }

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
