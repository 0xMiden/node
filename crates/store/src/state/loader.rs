//! Tree loading logic for the store state.
//!
//! This module handles loading and initializing the Merkle trees (account tree, nullifier tree,
//! and SMT forest) from `RocksDB`. Existing trees are loaded from disk; empty storage is rebuilt from
//! SQLite and persisted. Consistency checks detect divergence between `RocksDB` and SQLite after
//! loading.

use std::num::NonZeroUsize;
use std::path::Path;
use std::pin::pin;

use futures::TryStreamExt;
use miden_crypto::merkle::mmr::Mmr;
use miden_crypto::merkle::smt::{
    Backend,
    ForestPersistentBackend,
    PersistentBackendConfig,
    RocksDbStorage,
    SmtStorageReader,
};
use miden_node_tracing::{info, instrument};
use miden_node_utils::clap::RocksDbOptions;
use miden_protocol::account::{AccountId, AccountStorageHeader, StorageSlotType};
use miden_protocol::block::account_tree::{AccountIdKey, AccountTree};
use miden_protocol::block::nullifier_tree::NullifierTree;
use miden_protocol::block::{BlockHeader, BlockNumber, Blockchain, SignedBlock};
use miden_protocol::crypto::merkle::smt::{LargeSmt, LargeSmtError, SmtStorage};
use miden_protocol::{Felt, Word};

use crate::account_state_forest::AccountStateForest;
use crate::db::queries::{
    AccountCommitmentsPaged,
    NullifiersPaged,
    PublicAccountIdsPaged,
    PublicAccountStateRootsPaged,
};
use crate::db::{BlockHeaderCommitment, Db};
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
pub type TreeStorage = RocksDbStorage;

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

// PERSISTENT STORAGE LOADING
// ================================================================================================

/// Opens `RocksDB` storage for an account or nullifier tree.
#[instrument(
    name = "open_tree_storage",
    fields(path = domain),
)]
pub fn open_tree_storage(
    data_dir: &Path,
    storage_options: &RocksDbOptions,
    domain: &'static str,
) -> Result<RocksDbStorage, StateInitializationError> {
    let storage_path = data_dir.join(domain);
    let config = storage_options.with_path(&storage_path);
    fs_err::create_dir_all(&storage_path)
        .map_err(|e| StateInitializationError::AccountTreeIoError(e.to_string()))?;
    RocksDbStorage::open(config)
        .map_err(|e| StateInitializationError::AccountTreeIoError(e.to_string()))
}

/// Loads the account tree from `RocksDB`, populating empty storage from SQLite.
#[instrument]
pub async fn load_account_tree(
    storage: RocksDbStorage,
    db: &Db,
) -> Result<AccountTree<LargeSmt<RocksDbStorage>>, StateInitializationError> {
    let has_data = storage
        .has_leaves()
        .map_err(|e| StateInitializationError::AccountTreeIoError(e.to_string()))?;
    if has_data {
        let smt = load_smt(storage)?;
        return AccountTree::new(smt).map_err(StateInitializationError::FailedToCreateAccountsTree);
    }

    info!("RocksDB account tree storage is empty, populating from SQLite");

    let mut smt = LargeSmt::with_entries(storage, std::iter::empty())
        .map_err(account_tree_large_smt_error_to_init_error)?;

    // Load account commitments in pages to avoid loading millions of entries at once
    let mut pages =
        pin!(db.pages(AccountCommitmentsPaged { page_size: ACCOUNT_COMMITMENTS_PAGE_SIZE }, None));
    while let Some(commitments) = pages.try_next().await? {
        let entries = commitments
            .into_iter()
            .map(|(id, commitment)| (AccountIdKey::from(id).as_word(), commitment));

        let mutations = smt
            .compute_mutations(entries)
            .map_err(account_tree_large_smt_error_to_init_error)?;
        smt.apply_mutations(mutations)
            .map_err(account_tree_large_smt_error_to_init_error)?;
    }

    AccountTree::new(smt).map_err(StateInitializationError::FailedToCreateAccountsTree)
}

/// Loads the nullifier tree from `RocksDB`, populating empty storage from SQLite.
#[instrument]
pub async fn load_nullifier_tree(
    storage: RocksDbStorage,
    db: &Db,
) -> Result<NullifierTree<LargeSmt<RocksDbStorage>>, StateInitializationError> {
    let has_data = storage
        .has_leaves()
        .map_err(|e| StateInitializationError::NullifierTreeIoError(e.to_string()))?;
    if has_data {
        let smt = load_smt(storage)?;
        return Ok(NullifierTree::new_unchecked(smt));
    }

    info!("RocksDB nullifier tree storage is empty, populating from SQLite");

    let mut smt = LargeSmt::with_entries(storage, std::iter::empty())
        .map_err(account_tree_large_smt_error_to_init_error)?;

    // Load nullifiers in pages to avoid loading millions of entries at once
    let mut pages = pin!(db.pages(NullifiersPaged { page_size: NULLIFIERS_PAGE_SIZE }, None));
    while let Some(nullifiers) = pages.try_next().await? {
        let entries = nullifiers
            .into_iter()
            .map(|info| (info.nullifier.as_word(), block_num_to_nullifier_leaf(info.block_num)));

        let mutations = smt
            .compute_mutations(entries)
            .map_err(account_tree_large_smt_error_to_init_error)?;
        smt.apply_mutations(mutations)
            .map_err(account_tree_large_smt_error_to_init_error)?;
    }

    Ok(NullifierTree::new_unchecked(smt))
}

/// Opens `RocksDB` storage for the account state forest.
#[instrument(
    name = "open_forest_storage",
    fields(path = domain),
)]
pub fn open_account_state_forest_storage(
    data_dir: &Path,
    storage_options: &RocksDbOptions,
    domain: &'static str,
) -> Result<ForestPersistentBackend, StateInitializationError> {
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

/// Loads the account state forest from `RocksDB`, populating empty storage from SQLite.
#[instrument(
    fields(
        block.number = block_num,
    ),
)]
pub async fn load_account_state_forest(
    storage: ForestPersistentBackend,
    db: &Db,
    block_num: BlockNumber,
) -> Result<AccountStateForest<ForestPersistentBackend>, StateInitializationError> {
    let mut forest = AccountStateForest::from_backend(storage)
        .map_err(|e| StateInitializationError::AccountStateForestIoError(e.to_string()))?;

    if forest.lineage_count() != 0 {
        return Ok(forest);
    }

    info!("RocksDB account state forest storage is empty, populating from SQLite");
    rebuild_account_state_forest(&mut forest, db, block_num).await?;
    Ok(forest)
}

// HELPER FUNCTIONS
// ================================================================================================

/// Loads an SMT from persistent storage.
pub fn load_smt<S: SmtStorage>(storage: S) -> Result<LargeSmt<S>, StateInitializationError> {
    LargeSmt::load(storage).map_err(account_tree_large_smt_error_to_init_error)
}

// TREE LOADING FUNCTIONS
// ================================================================================================

/// Loads the blockchain MMR from all block headers in the database.
#[instrument(target = "miden::storage")]
pub async fn load_mmr(db: &Db) -> Result<Blockchain, StateInitializationError> {
    let latest_header = db.select_chain_tip().await?;
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
) -> Result<(), StateInitializationError> {
    let Some(latest_header) = latest_header else {
        return Err(StateInitializationError::GenesisBlockMissing);
    };

    let block_num = latest_header.block_num();
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
#[instrument(
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

    let mut pages =
        pin!(db.pages(PublicAccountIdsPaged { page_size: PUBLIC_ACCOUNT_IDS_PAGE_SIZE }, None));
    while let Some(account_ids) = pages.try_next().await? {
        let mut patches = Vec::with_capacity(account_ids.len());
        for account_id in account_ids {
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
    }

    Ok(())
}

// CONSISTENCY VERIFICATION
// ================================================================================================

/// Checks the loaded account and nullifier tree roots against the committed tip.
#[instrument]
pub(super) fn verify_tree_consistency(
    account_tree_root: Word,
    nullifier_tree_root: Word,
    header: &BlockHeader,
) -> Result<(), StateInitializationError> {
    let block_num = header.block_num();
    if account_tree_root != header.account_root() {
        return Err(StateInitializationError::TreeStorageDiverged {
            tree_name: "Account",
            block_num,
            tree_root: account_tree_root,
            block_root: header.account_root(),
        });
    }

    if nullifier_tree_root != header.nullifier_root() {
        return Err(StateInitializationError::TreeStorageDiverged {
            tree_name: "Nullifier",
            block_num,
            tree_root: nullifier_tree_root,
            block_root: header.nullifier_root(),
        });
    }

    Ok(())
}

/// Brings the persisted trees up to the SQLite tip by replaying the latest block where needed.
///
/// The writer commits each block to SQLite before updating the trees. It finishes those updates
/// before starting the next block, so an interrupted write can leave a tree one block behind.
#[instrument(fields(block.number = header.block_num()))]
pub(super) async fn sync_trees_to_tip(
    db: &Db,
    blocks: &crate::blocks::BlockStore,
    header: &BlockHeader,
    accounts: &mut AccountTree<LargeSmt<RocksDbStorage>>,
    nullifiers: &mut NullifierTree<LargeSmt<RocksDbStorage>>,
    forest: &mut AccountStateForest<ForestPersistentBackend>,
) -> Result<(), StateInitializationError> {
    let block = load_committed_block(blocks, header).await?;
    if accounts.root() != header.account_root() {
        replay_account_tree(accounts, &block)?;
    }
    if nullifiers.root() != header.nullifier_root() {
        replay_nullifier_tree(nullifiers, &block)?;
    }
    recover_forest(forest, db, &block).await
}

/// Loads the block body for the tip identified by SQLite.
async fn load_committed_block(
    blocks: &crate::blocks::BlockStore,
    header: &BlockHeader,
) -> Result<SignedBlock, StateInitializationError> {
    use StateInitializationError::BlockRecovery;
    let height = header.block_num();
    let bytes = blocks
        .load_block(height)
        .await
        .map_err(StateInitializationError::BlockStoreLoadError)?
        .ok_or_else(|| BlockRecovery(format!("missing block {height}")))?;
    let block: SignedBlock =
        miden_node_persistence::decode(&bytes).map_err(|e| BlockRecovery(e.to_string()))?;
    if block.header().commitment() != header.commitment() {
        return Err(BlockRecovery(format!("block {height} differs from SQLite")));
    }
    block.validate(None).map_err(|e| BlockRecovery(e.to_string()))?;
    Ok(block)
}

/// Applies the account commitments once their computed root matches the block header.
#[instrument(fields(block.number = block.header().block_num()))]
fn replay_account_tree(
    accounts: &mut AccountTree<LargeSmt<RocksDbStorage>>,
    block: &SignedBlock,
) -> Result<(), StateInitializationError> {
    use StateInitializationError::BlockRecovery;
    let header = block.header();
    let height = header.block_num();
    let body = block.body();
    let update = accounts
        .compute_mutations(
            body.updated_accounts()
                .iter()
                .map(|a| (a.account_id(), a.final_state_commitment())),
        )
        .map_err(|e| BlockRecovery(e.to_string()))?;
    if update.as_mutation_set().root() != header.account_root() {
        return Err(BlockRecovery(format!("account root differs after replaying block {height}")));
    }
    accounts.apply_mutations(update).map_err(|e| BlockRecovery(e.to_string()))?;
    Ok(())
}

/// Applies the block's nullifiers after checking their computed root.
#[instrument(fields(block.number = block.header().block_num()))]
fn replay_nullifier_tree(
    nullifiers: &mut NullifierTree<LargeSmt<RocksDbStorage>>,
    block: &SignedBlock,
) -> Result<(), StateInitializationError> {
    use StateInitializationError::BlockRecovery;
    let header = block.header();
    let height = header.block_num();
    let body = block.body();
    let update =
        nullifiers.compute_mutations(body.created_nullifiers().iter().map(|n| (*n, height)))?;
    if update.as_mutation_set().root() != header.nullifier_root() {
        return Err(BlockRecovery(format!(
            "nullifier root differs after replaying block {height}"
        )));
    }
    nullifiers.apply_mutations(update)?;
    Ok(())
}

/// Replays the forest batch if a public account touched by the block is missing its expected state.
///
/// The forest writes all changes for a block atomically and has no last-applied block marker.
/// A public account update can leave its vault and storage maps unchanged, so a match for one
/// account is inconclusive. On the first missing tree or root mismatch, recovery assumes the
/// whole batch was missed and checks its replayed roots against SQLite before writing it.
async fn recover_forest(
    forest: &mut AccountStateForest<ForestPersistentBackend>,
    db: &Db,
    block: &SignedBlock,
) -> Result<(), StateInitializationError> {
    use StateInitializationError::BlockRecovery;
    let height = block.header().block_num();
    let body = block.body();
    for update in body.updated_accounts() {
        if let miden_protocol::account::AccountUpdateDetails::Public(_) = update.details() {
            let id = update.account_id();
            let (account, storage) = db
                .select_account_header_with_storage_header_at_block(
                    id,
                    super::ScopedBlockNum::new(height),
                )
                .await?
                .ok_or_else(|| BlockRecovery(format!("missing account {id} at block {height}")))?;
            if verify_account_state_forest_record(forest, id, account.vault_root(), &storage)
                .is_err()
            {
                return replay_forest(forest, db, block).await;
            }
        }
    }
    Ok(())
}

/// Computes the tip block's forest update and verifies it before writing.
///
/// The block header has no single root for the account state forest. SQLite records each public
/// account's vault and storage-map roots, so replay checks the computed roots against those values.
#[instrument(fields(block.number = block.header().block_num()))]
async fn replay_forest(
    forest: &mut AccountStateForest<ForestPersistentBackend>,
    db: &Db,
    block: &miden_protocol::block::SignedBlock,
) -> Result<(), StateInitializationError> {
    use StateInitializationError::BlockRecovery;
    use miden_protocol::account::AccountUpdateDetails;
    let height = block.header().block_num();
    let body = block.body();
    let patches = body.updated_accounts().iter().filter_map(|a| match a.details() {
        AccountUpdateDetails::Public(patch) => Some(patch.clone()),
        AccountUpdateDetails::Private => None,
    });
    let created = body
        .transactions()
        .iter()
        .flat_map(miden_protocol::transaction::OrderedTransactionHeaders::created_account_ids)
        .collect();
    let update = forest
        .compute_block_update_mutations(height, patches, &created)
        .map_err(|e| BlockRecovery(e.to_string()))?;
    for (&id, roots) in &update.account_states {
        let (account, storage) = db
            .select_account_header_with_storage_header_at_block(
                id,
                super::ScopedBlockNum::new(height),
            )
            .await?
            .ok_or_else(|| BlockRecovery(format!("missing account {id} at block {height}")))?;
        if roots.vault_root != account.vault_root()
            || roots.storage_map_roots.iter().any(|(name, root)| {
                storage
                    .find_slot_header_by_name(name)
                    .filter(|slot| slot.slot_type() == StorageSlotType::Map)
                    .map(miden_protocol::account::StorageSlotHeader::value)
                    != Some(*root)
            })
        {
            return Err(BlockRecovery(format!(
                "replayed roots for account {id} differ from SQLite at block {height}"
            )));
        }
    }
    forest
        .apply_precomputed_block_update(height, update)
        .map_err(|e| BlockRecovery(e.to_string()))?;
    Ok(())
}

/// Verifies that the account state forest matches latest public account roots from SQLite.
///
/// This check ensures persisted account state forest has not diverged from the latest
/// account states in SQLite. When the forest is rebuilt from SQLite, it will naturally
/// match; when loaded from `RocksDB`, this catches corruption or incomplete shutdown.
#[instrument]
pub async fn verify_account_state_forest_consistency(
    forest: &AccountStateForest<impl Backend + Sync>,
    db: &Db,
) -> Result<(), StateInitializationError> {
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
) -> Result<(), StateInitializationError> {
    let forest_vault_root = forest
        .latest_tree_root(account_id, None)
        .ok_or(StateInitializationError::MissingForestTree { account_id, slot: None })?;
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

        let forest_root =
            forest.latest_tree_root(account_id, Some(slot.name())).ok_or_else(|| {
                StateInitializationError::MissingForestTree {
                    account_id,
                    slot: Some(slot.name().to_string()),
                }
            })?;
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
    use miden_crypto::merkle::smt::BackendReader;
    use miden_protocol::account::{
        Account,
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
                    let signatures = miden_protocol::block::BlockSignatures::sign(
                        std::slice::from_ref(&signing_key),
                        header.commitment(),
                    );
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

        let error = load_mmr(&db)
            .await
            .expect_err("startup MMR load should reject inconsistent block headers");

        assert_matches::assert_matches!(
            error,
            StateInitializationError::ChainMmrStorageDiverged { .. }
        );
    }

    #[test]
    fn account_state_forest_consistency_detects_storage_map_root_mismatch() {
        let account = forest_accounts().remove(0);
        let account_id = account.id();
        let mut forest = AccountStateForest::new();
        forest
            .apply_rebuild_updates(
                BlockNumber::GENESIS,
                [miden_protocol::account::AccountPatch::try_from(account.clone()).unwrap()],
            )
            .unwrap();
        let slot_name = StorageSlotName::mock(0);
        let expected_storage_root = Word::from([1, 0, 0, 0u32]);
        let storage_header = AccountStorageHeader::new(vec![StorageSlotHeader::new(
            slot_name.clone(),
            StorageSlotType::Map,
            expected_storage_root,
        )])
        .expect("storage header should be valid");

        let error = verify_account_state_forest_record(
            &forest,
            account_id,
            account.vault().root(),
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
                && Some(forest_root) == forest.latest_tree_root(account_id, Some(&slot_name))
                && database_root == expected_storage_root
        );
    }

    #[test]
    fn account_state_forest_consistency_detects_vault_root_mismatch() {
        let account = forest_accounts().remove(0);
        let account_id = account.id();
        let mut forest = AccountStateForest::new();
        forest
            .apply_rebuild_updates(
                BlockNumber::GENESIS,
                [miden_protocol::account::AccountPatch::try_from(account.clone()).unwrap()],
            )
            .unwrap();
        let expected_vault_root = Word::from([2, 0, 0, 0u32]);
        let storage_header =
            AccountStorageHeader::new(Vec::new()).expect("storage header should be valid");

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
                && forest_root == account.vault().root()
                && database_root == expected_vault_root
        );
    }

    fn forest_accounts() -> Vec<Account> {
        use miden_protocol::account::{
            AccountCode,
            AccountStorage,
            StorageMap,
            StorageMapKey,
            StorageSlot,
        };
        use miden_protocol::asset::{AssetVault, FungibleAsset};
        use miden_protocol::testing::account_id::{
            ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
            ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2,
        };

        [
            ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
            ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2,
        ]
        .into_iter()
        .enumerate()
        .map(|(index, id)| {
            let asset = FungibleAsset::new(
                ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into().unwrap(),
                100 + index as u64,
            )
            .unwrap();
            let slots = (0..2)
                .map(|slot| {
                    StorageSlot::with_map(
                        StorageSlotName::mock(slot),
                        StorageMap::with_entries([(
                            StorageMapKey::from_index(1),
                            Word::from([index as u32 + slot as u32 + 1, 0, 0, 0]),
                        )])
                        .unwrap(),
                    )
                })
                .collect();
            Account::new_existing(
                id.try_into().unwrap(),
                AssetVault::new(&[asset.into()]).unwrap(),
                AccountStorage::new(slots).unwrap(),
                AccountCode::mock(),
                Felt::ONE,
            )
        })
        .collect()
    }

    fn assert_forest_accounts(
        forest: &AccountStateForest<impl BackendReader>,
        accounts: &[Account],
    ) {
        use miden_node_proto::domain::account::{AccountVaultDetails, StorageMapEntries};
        use miden_protocol::account::{StorageMapKey, StorageSlotContent};
        use miden_protocol::asset::AssetId;
        use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2;

        for account in accounts {
            let mut ids = account.vault().assets().map(|asset| asset.id()).collect::<Vec<_>>();
            ids.push(AssetId::new_fungible(
                ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2.try_into().unwrap(),
            ));
            let AccountVaultDetails::Partial { vault, .. } = forest
                .get_vault_details_for_assets(account.id(), BlockNumber::GENESIS, ids.clone())
                .unwrap()
            else {
                panic!("expected vault witnesses")
            };
            assert_eq!(vault.root(), account.vault().root());
            for id in ids {
                assert_eq!(vault.open(id).unwrap(), account.vault().open(id));
            }
            for slot in account.storage().slots() {
                let StorageSlotContent::Map(map) = slot.content() else {
                    unreachable!()
                };
                let keys = vec![StorageMapKey::from_index(1), StorageMapKey::from_index(2)];
                let details = forest
                    .get_storage_map_details_for_keys(
                        account.id(),
                        slot.name().clone(),
                        BlockNumber::GENESIS,
                        keys.clone(),
                    )
                    .unwrap()
                    .unwrap();
                let StorageMapEntries::PartialMap { partial_smt, .. } = details.entries else {
                    panic!("expected map witnesses")
                };
                assert_eq!(partial_smt.root(), map.root());
                for key in keys {
                    assert_eq!(
                        partial_smt.get_value(&key.hash().as_word()).unwrap(),
                        map.get(&key)
                    );
                }
            }
        }
    }

    #[test]
    fn eidos_forest_reopens_with_vault_and_storage_proofs() {
        use miden_protocol::account::AccountPatch;
        let root = tempfile::tempdir().unwrap();
        let accounts = forest_accounts();
        let config = PersistentBackendConfig::new(root.path()).unwrap();
        let mut forest = AccountStateForest::from_backend(
            ForestPersistentBackend::load(config.clone()).unwrap(),
        )
        .unwrap();
        forest
            .apply_rebuild_updates(
                BlockNumber::GENESIS,
                accounts.iter().cloned().map(|account| AccountPatch::try_from(account).unwrap()),
            )
            .unwrap();
        assert_forest_accounts(&forest, &accounts);
        drop(forest);
        let reopened =
            AccountStateForest::from_backend(ForestPersistentBackend::load(config).unwrap())
                .unwrap();
        assert_forest_accounts(&reopened, &accounts);
    }

    #[tokio::test]
    async fn eidos_forest_rebuild_matches_persisted_state() {
        use miden_node_utils::fee::{test_fee_params, test_protocol_config};
        use miden_protocol::block::ValidatorConfig;

        use crate::genesis::GenesisState;

        let root = tempfile::tempdir().unwrap();
        let accounts = forest_accounts();
        let signer = SigningKey::new();
        let genesis = GenesisState::new(
            accounts.clone(),
            test_fee_params(),
            0,
            ValidatorConfig::new(vec![signer.public_key()], 1).unwrap(),
            test_protocol_config(),
        )
        .into_block()
        .unwrap();
        let path = root.path().join("store.sqlite3");
        Db::bootstrap(path.clone(), genesis).await.unwrap();
        let db = Db::load(path).await.unwrap();
        let config = PersistentBackendConfig::new(root.path().join("forest")).unwrap();
        let forest = load_account_state_forest(
            ForestPersistentBackend::load(config.clone()).unwrap(),
            &db,
            BlockNumber::GENESIS,
        )
        .await
        .unwrap();
        assert_forest_accounts(&forest, &accounts);
        drop(forest);
        let reopened = load_account_state_forest(
            ForestPersistentBackend::load(config).unwrap(),
            &db,
            BlockNumber::GENESIS,
        )
        .await
        .unwrap();
        assert_forest_accounts(&reopened, &accounts);
    }
}
