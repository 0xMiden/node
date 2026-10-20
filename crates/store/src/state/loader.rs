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
use std::pin::pin;

use anyhow::Context;
use fn_error_context::context;
use futures::TryStreamExt;
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
use miden_node_tracing::info;
use miden_node_tracing::miden_instrument;
#[cfg(feature = "rocksdb")]
use miden_node_utils::clap::RocksDbOptions;
use miden_protocol::account::{AccountId, AccountStorageHeader, StorageSlotType};
use miden_protocol::block::account_tree::{AccountIdKey, AccountTree};
use miden_protocol::block::nullifier_tree::NullifierTree;
use miden_protocol::block::{BlockHeader, BlockNumber, Blockchain};
#[cfg(not(feature = "rocksdb"))]
use miden_protocol::crypto::merkle::smt::MemoryStorage;
use miden_protocol::crypto::merkle::smt::{LargeSmt, SmtStorage};
use miden_protocol::{Felt, Word};

use crate::COMPONENT;
#[cfg(feature = "rocksdb")]
use crate::LOG_TARGET;
use crate::account_state_forest::AccountStateForest;
use crate::db::queries::{
    AccountCommitmentsPaged,
    NullifiersPaged,
    PublicAccountIdsPaged,
    PublicAccountStateRootsPaged,
};
use crate::db::{BlockHeaderCommitment, Db};

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
    ) -> anyhow::Result<Self>;

    /// Loads an account tree, either from persistent storage or by rebuilding from DB.
    fn load_account_tree(
        self,
        db: &Db,
    ) -> impl Future<Output = anyhow::Result<AccountTree<LargeSmt<Self>>>> + Send;

    /// Loads a nullifier tree, either from persistent storage or by rebuilding from DB.
    fn load_nullifier_tree(
        self,
        db: &Db,
    ) -> impl Future<Output = anyhow::Result<NullifierTree<LargeSmt<Self>>>> + Send;
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
    ) -> anyhow::Result<Self>;

    /// Loads the account state forest, either from persistent storage or by rebuilding from DB.
    fn load_account_state_forest(
        self,
        db: &Db,
        block_num: BlockNumber,
    ) -> impl Future<Output = anyhow::Result<AccountStateForest<Self>>> + Send;
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
    ) -> anyhow::Result<Self> {
        Ok(MemoryStorage::default())
    }

    #[context("failed to load account tree")]
    #[miden_instrument(
        target = COMPONENT,
    )]
    async fn load_account_tree(self, db: &Db) -> anyhow::Result<AccountTree<LargeSmt<Self>>> {
        let mut smt = LargeSmt::with_entries(self, std::iter::empty())?;

        // Load account commitments in pages to avoid loading millions of entries at once
        let mut pages = pin!(
            db.pages(AccountCommitmentsPaged { page_size: ACCOUNT_COMMITMENTS_PAGE_SIZE }, None)
        );
        while let Some(commitments) = pages.try_next().await? {
            let entries = commitments
                .into_iter()
                .map(|(id, commitment)| (AccountIdKey::from(id).as_word(), commitment));

            let mutations = smt.compute_mutations(entries)?;
            smt.apply_mutations(mutations)?;
        }

        AccountTree::new(smt).context("failed to create accounts tree")
    }

    // TODO: Make the loading methodology for account and nullifier trees consistent. Currently we
    // use `NullifierTree::new_unchecked()` for nullifiers but `AccountTree::new()` for accounts.
    // Consider using `NullifierTree::with_storage_from_entries()` for consistency.
    #[context("failed to load nullifier tree")]
    #[miden_instrument(
        target = COMPONENT,
    )]
    async fn load_nullifier_tree(self, db: &Db) -> anyhow::Result<NullifierTree<LargeSmt<Self>>> {
        let mut smt = LargeSmt::with_entries(self, std::iter::empty())?;

        // Load nullifiers in pages to avoid loading millions of entries at once
        let mut pages = pin!(db.pages(NullifiersPaged { page_size: NULLIFIERS_PAGE_SIZE }, None));
        while let Some(nullifiers) = pages.try_next().await? {
            let entries = nullifiers.into_iter().map(|info| {
                (info.nullifier.as_word(), block_num_to_nullifier_leaf(info.block_num))
            });

            let mutations = smt.compute_mutations(entries)?;
            smt.apply_mutations(mutations)?;
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
    #[context("failed to open {} storage in {}", domain, data_dir.display())]
    #[miden_instrument(
        target = COMPONENT,
        name = "open_tree_storage",
        fields(path = domain),
    )]
    fn create(
        data_dir: &Path,
        storage_options: &Self::Config,
        domain: &'static str,
    ) -> anyhow::Result<Self> {
        let storage_path = data_dir.join(domain);
        let config = storage_options.with_path(&storage_path);
        fs_err::create_dir_all(&storage_path)?;
        Ok(RocksDbStorage::open(config)?)
    }

    #[context("failed to load account tree")]
    #[miden_instrument(
        target = COMPONENT,
    )]
    async fn load_account_tree(self, db: &Db) -> anyhow::Result<AccountTree<LargeSmt<Self>>> {
        // If RocksDB storage has data, load from it directly

        let has_data = self.has_leaves().context("failed to inspect stored leaves")?;
        if has_data {
            let smt = load_smt(self)?;
            return AccountTree::new(smt).context("failed to create accounts tree");
        }

        info!(target: LOG_TARGET, "RocksDB account tree storage is empty, populating from SQLite");

        let mut smt = LargeSmt::with_entries(self, std::iter::empty())?;

        // Load account commitments in pages to avoid loading millions of entries at once
        let mut pages = pin!(
            db.pages(AccountCommitmentsPaged { page_size: ACCOUNT_COMMITMENTS_PAGE_SIZE }, None)
        );
        while let Some(commitments) = pages.try_next().await? {
            let entries = commitments
                .into_iter()
                .map(|(id, commitment)| (AccountIdKey::from(id).as_word(), commitment));

            let mutations = smt.compute_mutations(entries)?;
            smt.apply_mutations(mutations)?;
        }

        AccountTree::new(smt).context("failed to create accounts tree")
    }

    #[context("failed to load nullifier tree")]
    #[miden_instrument(
        target = COMPONENT,
    )]
    async fn load_nullifier_tree(self, db: &Db) -> anyhow::Result<NullifierTree<LargeSmt<Self>>> {
        // If RocksDB storage has data, load from it directly

        let has_data = self.has_leaves().context("failed to inspect stored leaves")?;
        if has_data {
            let smt = load_smt(self)?;
            return Ok(NullifierTree::new_unchecked(smt));
        }

        info!(target: LOG_TARGET, "RocksDB nullifier tree storage is empty, populating from SQLite");

        let mut smt = LargeSmt::with_entries(self, std::iter::empty())?;

        // Load nullifiers in pages to avoid loading millions of entries at once
        let mut pages = pin!(db.pages(NullifiersPaged { page_size: NULLIFIERS_PAGE_SIZE }, None));
        while let Some(nullifiers) = pages.try_next().await? {
            let entries = nullifiers.into_iter().map(|info| {
                (info.nullifier.as_word(), block_num_to_nullifier_leaf(info.block_num))
            });

            let mutations = smt.compute_mutations(entries)?;
            smt.apply_mutations(mutations)?;
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
    ) -> anyhow::Result<Self> {
        Ok(ForestInMemoryBackend::new())
    }

    #[context("failed to load account state forest")]
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
    ) -> anyhow::Result<AccountStateForest<Self>> {
        let mut forest = AccountStateForest::from_backend(self)?;
        rebuild_account_state_forest(&mut forest, db, block_num).await?;
        Ok(forest)
    }
}

#[cfg(feature = "rocksdb")]
impl AccountForestLoader for ForestPersistentBackend {
    type Config = RocksDbOptions;

    // Opening RocksDB replays unflushed WAL segments and fills the table cache, which can take
    // seconds; the span makes this cost visible in startup traces.
    #[context("failed to open {} storage in {}", domain, data_dir.display())]
    #[miden_instrument(
        target = COMPONENT,
        name = "open_forest_storage",
        fields(path = domain),
    )]
    fn create(
        data_dir: &Path,
        storage_options: &Self::Config,
        domain: &'static str,
    ) -> anyhow::Result<Self> {
        let storage_path = data_dir.join(domain);
        fs_err::create_dir_all(&storage_path)?;

        let max_open_files = usize::try_from(storage_options.max_open_fds).with_context(|| {
            format!(
                "invalid account state forest RocksDB max_open_fds: {}",
                storage_options.max_open_fds
            )
        })?;
        let config = PersistentBackendConfig::new(&storage_path)?
            .with_cache_size_bytes(storage_options.cache_size_in_bytes)
            .with_max_open_files(max_open_files);

        Ok(ForestPersistentBackend::load(config)?)
    }

    #[context("failed to load account state forest")]
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
    ) -> anyhow::Result<AccountStateForest<Self>> {
        let mut forest = AccountStateForest::from_backend(self)?;

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
pub fn load_smt<S: SmtStorage>(storage: S) -> anyhow::Result<LargeSmt<S>> {
    LargeSmt::load(storage).context("failed to load persisted SMT")
}

// TREE LOADING FUNCTIONS
// ================================================================================================

/// Loads the blockchain MMR from all block headers in the database.
#[context("failed to load chain MMR")]
#[miden_instrument(
    target = COMPONENT,
)]
pub async fn load_mmr(db: &Db) -> anyhow::Result<Blockchain> {
    let latest_header = db.select_block_header_by_block_num(None).await?;
    let block_commitments = db.select_all_block_header_commitments().await?;

    // SAFETY: We assume the loaded MMR is valid and does not have more than u32::MAX entries.
    let mmr = Mmr::try_from_iter(block_commitments.into_iter().map(BlockHeaderCommitment::word))
        .expect("loaded MMR exceeds maximum allowed size");
    let chain_mmr = Blockchain::from_mmr_unchecked(mmr);

    verify_chain_mmr_consistency(&chain_mmr, latest_header.as_ref())?;

    Ok(chain_mmr)
}

fn verify_chain_mmr_consistency(
    chain_mmr: &Blockchain,
    latest_header: Option<&BlockHeader>,
) -> anyhow::Result<()> {
    let Some(latest_header) = latest_header else {
        anyhow::bail!("genesis block missing. The database should be bootstrapped first.");
    };

    let block_num = latest_header.block_num();
    let expected_chain_commitment = latest_header.chain_commitment();
    let actual_chain_commitment = chain_mmr
        .peaks_at(block_num)
        .with_context(|| format!("loaded chain MMR cannot produce peaks for block {block_num}"))?
        .hash_peaks();

    if actual_chain_commitment != expected_chain_commitment {
        anyhow::bail!(
            "chain MMR commitment ({actual_chain_commitment:?}) does not match expected chain \
             commitment ({expected_chain_commitment:?}) from block {block_num}"
        );
    }

    Ok(())
}

/// Rebuilds SMT forest with storage map and vault Merkle paths for all public accounts.
#[context("failed to rebuild account state forest")]
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
) -> anyhow::Result<()> {
    use miden_protocol::account::AccountPatch;

    let mut pages =
        pin!(db.pages(PublicAccountIdsPaged { page_size: PUBLIC_ACCOUNT_IDS_PAGE_SIZE }, None));
    while let Some(account_ids) = pages.try_next().await? {
        let mut patches = Vec::with_capacity(account_ids.len());
        for account_id in account_ids {
            // TODO: Loading the full account from the database is inefficient and will need to go
            // away. <https://github.com/0xMiden/node/issues/1556>
            let account_info = db.select_account(account_id).await?;
            let account = account_info.details.with_context(|| {
                format!("public account {account_id} is missing details in database")
            })?;

            // Convert the full account to a full-state patch
            let patch = AccountPatch::try_from(account)
                .with_context(|| format!("failed to convert account {account_id} to patch"))?;

            patches.push(patch);
        }

        forest
            .apply_rebuild_updates(block_num, patches)
            .context("failed to apply account state forest rebuild updates")?;
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
/// Returns an error with the mismatched roots and recovery instructions if any root differs.
#[miden_instrument(
    target = COMPONENT,
)]
pub async fn verify_tree_consistency(
    account_tree_root: Word,
    nullifier_tree_root: Word,
    db: &Db,
) -> anyhow::Result<()> {
    // Fetch the latest block header to get the expected roots
    let latest_header = db.select_block_header_by_block_num(None).await?;

    let (block_num, expected_account_root, expected_nullifier_root) = latest_header
        .map(|header| (header.block_num(), header.account_root(), header.nullifier_root()))
        .unwrap_or_default();

    // Verify account tree root
    if account_tree_root != expected_account_root {
        anyhow::bail!(
            "Account SMT root ({account_tree_root:?}) does not match expected root from block \
             {block_num} ({expected_account_root:?}). Delete the tree storage directories and \
             restart the node to rebuild from the database."
        );
    }

    // Verify nullifier tree root
    if nullifier_tree_root != expected_nullifier_root {
        anyhow::bail!(
            "Nullifier SMT root ({nullifier_tree_root:?}) does not match expected root from block \
             {block_num} ({expected_nullifier_root:?}). Delete the tree storage directories and \
             restart the node to rebuild from the database."
        );
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
) -> anyhow::Result<()> {
    use rayon::iter::{IntoParallelIterator, ParallelIterator};

    let mut pages = pin!(
        db.pages(PublicAccountStateRootsPaged { page_size: PUBLIC_ACCOUNT_IDS_PAGE_SIZE }, None)
    );
    while let Some(accounts) = pages.try_next().await? {
        // Per-account checks are independent, so verify each page in parallel.
        accounts.into_par_iter().try_for_each(|account| {
            verify_account_state_forest_record(
                forest,
                account.account_id,
                account.vault_root,
                &account.storage_header,
            )
        })?;
    }

    Ok(())
}

fn verify_account_state_forest_record(
    forest: &AccountStateForest<impl Backend>,
    account_id: AccountId,
    vault_root: Word,
    storage_header: &AccountStorageHeader,
) -> anyhow::Result<()> {
    let forest_vault_root = forest.get_latest_vault_root(account_id);
    if forest_vault_root != vault_root {
        anyhow::bail!(
            "account state forest vault root ({forest_vault_root}) does not match SQLite root \
             ({vault_root}) for account {account_id}. Delete the account state forest storage \
             directory and restart the node to rebuild from the database."
        );
    }

    for slot in storage_header.slots() {
        if slot.slot_type() != StorageSlotType::Map {
            continue;
        }

        let forest_root = forest.get_latest_storage_map_root(account_id, slot.name());
        let database_root = slot.value();
        if forest_root != database_root {
            anyhow::bail!(
                "account state forest root ({forest_root}) does not match SQLite root \
                 ({database_root}) for account {account_id}, slot {}. Delete the account state \
                 forest storage directory and restart the node to rebuild from the database.",
                slot.name(),
            );
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
    use crate::errors::DatabaseError;

    #[cfg(feature = "rocksdb")]
    #[test]
    fn opening_tree_storage_reports_domain_and_preserves_io_error() {
        use miden_node_tracing::ErrorReport;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(NULLIFIER_TREE_STORAGE_DIR);
        fs_err::write(&path, b"not a directory").unwrap();

        let error = TreeStorage::create(
            directory.path(),
            &RocksDbOptions::default(),
            NULLIFIER_TREE_STORAGE_DIR,
        )
        .map(|_| ())
        .expect_err("a file cannot be opened as a tree storage directory");

        let report = error.as_report();
        assert!(report.contains(NULLIFIER_TREE_STORAGE_DIR), "{report}");
        assert!(report.contains(&directory.path().display().to_string()), "{report}");
        assert!(error.downcast_ref::<std::io::Error>().is_some(), "{report}");
    }

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

        verify_chain_mmr_consistency(&blockchain, headers.last())
            .expect_err("corrupted chain MMR should be rejected");
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
            .write::<_, DatabaseError, _>("insert block headers", move |tx| {
                for header in &headers {
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

        load_mmr(&db).await.expect("consistent block headers should load");

        db.writer()
            .write::<_, DatabaseError, _>("corrupt block commitment", move |tx| {
                // Corrupt the stored commitment of one header so it disagrees with the header it
                // was stored alongside.
                tx.execute(
                    "UPDATE block_headers SET commitment = ?1 WHERE block_num = ?2",
                    &[&Word::from([42, 0, 0, 0u32]), &BlockNumber::from(2)],
                )?;

                Ok(())
            })
            .await
            .expect("test block commitment should be corrupted");

        load_mmr(&db)
            .await
            .expect_err("startup MMR load should reject inconsistent block headers");
    }

    #[test]
    fn account_state_forest_consistency_detects_storage_map_root_mismatch() {
        let account_id = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE)
            .expect("test account ID should be valid");
        let slot_name =
            StorageSlotName::new("account::balances").expect("slot name should be valid");
        let storage_header = |root| {
            AccountStorageHeader::new(vec![StorageSlotHeader::new(
                slot_name.clone(),
                StorageSlotType::Map,
                root,
            )])
            .expect("storage header should be valid")
        };
        let forest = AccountStateForest::new();

        verify_account_state_forest_record(
            &forest,
            account_id,
            AccountStateForest::empty_smt_root(),
            &storage_header(AccountStateForest::empty_smt_root()),
        )
        .expect("matching storage map roots should be accepted");

        verify_account_state_forest_record(
            &forest,
            account_id,
            AccountStateForest::empty_smt_root(),
            &storage_header(Word::from([1, 0, 0, 0u32])),
        )
        .expect_err("storage map root mismatch should be detected");
    }

    #[test]
    fn account_state_forest_consistency_detects_vault_root_mismatch() {
        let account_id = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE)
            .expect("test account ID should be valid");
        let expected_vault_root = Word::from([2, 0, 0, 0u32]);
        let storage_header =
            AccountStorageHeader::new(Vec::new()).expect("storage header should be valid");
        let forest = AccountStateForest::new();

        verify_account_state_forest_record(
            &forest,
            account_id,
            AccountStateForest::empty_smt_root(),
            &storage_header,
        )
        .expect("matching vault roots should be accepted");

        verify_account_state_forest_record(
            &forest,
            account_id,
            expected_vault_root,
            &storage_header,
        )
        .expect_err("vault root mismatch should be detected");
    }
}
