use std::hint::black_box;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use miden_large_smt_backend_rocksdb::{RocksDbConfig, RocksDbStorage};
use miden_node_store::AccountTreeWithHistory;
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::block::account_tree::{AccountTree, account_id_to_smt_key};
use miden_protocol::crypto::hash::rpo::Rpo256;
use miden_protocol::crypto::merkle::smt::LargeSmt;
use miden_protocol::testing::account_id::AccountIdBuilder;

/// Counter for creating unique `RocksDB` directories during benchmarking.
static DB_COUNTER: AtomicUsize = AtomicUsize::new(0);

// HELPER FUNCTIONS
// ================================================================================================

/// Returns the default base path for `RocksDB` benchmark storage.
fn default_storage_path() -> std::path::PathBuf {
    std::path::PathBuf::from("target/bench_rocksdb")
}

/// Creates a `RocksDB` storage instance for benchmarking.
///
/// # Arguments
/// * `base_path` - Base directory for `RocksDB` storage. Each call creates a unique subdirectory.
fn setup_storage(base_path: &Path) -> RocksDbStorage {
    let counter = DB_COUNTER.fetch_add(1, Ordering::SeqCst);
    let db_path = base_path.join(format!("bench_rocksdb_{counter}"));

    // Clean up the directory if it exists
    if db_path.exists() {
        fs_err::remove_dir_all(&db_path).ok();
    }
    fs_err::create_dir_all(&db_path).expect("Failed to create storage directory");

    RocksDbStorage::open(RocksDbConfig::new(db_path)).expect("RocksDB failed to open file")
}

/// Generates a deterministic word from a seed.
fn generate_word(seed: &mut [u8; 32]) -> Word {
    for byte in seed.iter_mut() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
    Rpo256::hash(seed)
}

/// Generates a deterministic `AccountId` from a seed.
fn generate_account_id(seed: &mut [u8; 32]) -> AccountId {
    for byte in seed.iter_mut() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
    AccountIdBuilder::new().build_with_seed(*seed)
}

// SETUP FUNCTIONS
// ================================================================================================

/// Sets up a vanilla `AccountTree` with specified number of accounts.
fn setup_vanilla_account_tree(
    num_accounts: usize,
    base_path: &Path,
) -> (AccountTree<LargeSmt<RocksDbStorage>>, Vec<AccountId>) {
    let mut seed = [0u8; 32];
    let mut account_ids = Vec::new();
    let mut entries = Vec::new();

    for _ in 0..num_accounts {
        let account_id = generate_account_id(&mut seed);
        let commitment = generate_word(&mut seed);
        account_ids.push(account_id);
        entries.push((account_id_to_smt_key(account_id), commitment));
    }

    let storage = setup_storage(base_path);
    let smt =
        LargeSmt::with_entries(storage, entries).expect("Failed to create LargeSmt from entries");
    let tree = AccountTree::new(smt).expect("Failed to create AccountTree");
    (tree, account_ids)
}

/// Sets up `AccountTreeWithHistory` with specified number of accounts and blocks.
fn setup_account_tree_with_history(
    num_accounts: usize,
    num_blocks: usize,
    base_path: &Path,
) -> (AccountTreeWithHistory<RocksDbStorage>, Vec<AccountId>) {
    let mut seed = [0u8; 32];
    let storage = setup_storage(base_path);
    let smt = LargeSmt::with_entries(storage, std::iter::empty())
        .expect("Failed to create empty LargeSmt");
    let account_tree = AccountTree::new(smt).expect("Failed to create AccountTree");
    let mut account_tree_hist = AccountTreeWithHistory::new(account_tree, BlockNumber::GENESIS);
    let mut account_ids = Vec::new();

    for _block in 0..num_blocks {
        let mutations: Vec<_> = (0..num_accounts)
            .map(|_| {
                let account_id = generate_account_id(&mut seed);
                let commitment = generate_word(&mut seed);
                if account_ids.len() < num_accounts {
                    account_ids.push(account_id);
                }
                (account_id, commitment)
            })
            .collect();

        account_tree_hist.compute_and_apply_mutations(mutations).unwrap();
    }

    (account_tree_hist, account_ids)
}

// VANILLA ACCOUNTTREE BENCHMARKS
// ================================================================================================

/// Benchmarks vanilla `AccountTree` open (query) operations.
/// This provides a baseline for comparison with historical access operations.
fn bench_vanilla_access(c: &mut Criterion) {
    let mut group = c.benchmark_group("account_tree_vanilla_access");
    let base_path = default_storage_path();

    let account_counts = [1, 10, 50, 100, 500, 1000];

    for &num_accounts in &account_counts {
        let (tree, account_ids) = setup_vanilla_account_tree(num_accounts, &base_path);

        group.bench_function(BenchmarkId::new("vanilla", num_accounts), |b| {
            let test_account = *account_ids.first().unwrap();
            b.iter(|| {
                tree.open(black_box(test_account));
            });
        });
    }

    group.finish();
}

/// Benchmarks vanilla `AccountTree` insertion (mutation) performance.
/// This provides a baseline for comparison with history-tracking insertion.
fn bench_vanilla_insertion(c: &mut Criterion) {
    let mut group = c.benchmark_group("account_tree_insertion");
    let base_path = default_storage_path();

    let account_counts = [1, 10, 50, 100, 500];

    for &num_accounts in &account_counts {
        group.bench_function(BenchmarkId::new("vanilla", num_accounts), |b| {
            b.iter(|| {
                let mut seed = [0u8; 32];
                let storage = setup_storage(&base_path);
                let smt = LargeSmt::with_entries(storage, std::iter::empty())
                    .expect("Failed to create empty LargeSmt");
                let mut tree = AccountTree::new(smt).expect("Failed to create AccountTree");
                let entries: Vec<_> = (0..num_accounts)
                    .map(|_| {
                        let account_id = generate_account_id(&mut seed);
                        let commitment = generate_word(&mut seed);
                        (account_id, commitment)
                    })
                    .collect();
                let mutations = tree.compute_mutations(black_box(entries)).unwrap();
                tree.apply_mutations(black_box(mutations)).unwrap();
            });
        });
    }

    group.finish();
}

// HISTORICAL ACCOUNTTREE BENCHMARKS
// ================================================================================================

/// Benchmarks historical access at different depths and account counts.
fn bench_historical_access(c: &mut Criterion) {
    let mut group = c.benchmark_group("account_tree_historical_access");
    let base_path = default_storage_path();

    let account_counts = [10, 100, 500, 2500];
    let block_depths = [0, 5, 10, 20, 32];

    for &num_accounts in &account_counts {
        for &block_depth in &block_depths {
            if block_depth > AccountTreeWithHistory::<RocksDbStorage>::MAX_HISTORY {
                continue;
            }

            let (tree_hist, account_ids) =
                setup_account_tree_with_history(num_accounts, block_depth + 1, &base_path);
            let current_block = tree_hist.block_number_latest();
            let target_block = current_block
                .checked_sub(u32::try_from(block_depth).unwrap())
                .unwrap_or(BlockNumber::GENESIS);

            if block_depth >= tree_hist.history_len() && block_depth > 0 {
                continue;
            }

            group.bench_function(
                BenchmarkId::new(format!("depth_{block_depth}"), num_accounts),
                |b| {
                    let test_account = *account_ids.first().unwrap();
                    b.iter(|| {
                        tree_hist.open_at(black_box(test_account), black_box(target_block));
                    });
                },
            );
        }
    }

    group.finish();
}

/// Benchmarks insertion performance with history tracking at different account counts.
fn bench_insertion_with_history(c: &mut Criterion) {
    let mut group = c.benchmark_group("account_tree_insertion");
    let base_path = default_storage_path();

    let account_counts = [1, 10, 50, 100, 500, 2500];

    for &num_accounts in &account_counts {
        group.bench_function(BenchmarkId::new("with_history", num_accounts), |b| {
            b.iter(|| {
                let mut seed = [0u8; 32];
                let storage = setup_storage(&base_path);
                let smt = LargeSmt::with_entries(storage, std::iter::empty())
                    .expect("Failed to create empty LargeSmt");
                let account_tree = AccountTree::new(smt).expect("Failed to create AccountTree");
                let mut tree = AccountTreeWithHistory::new(account_tree, BlockNumber::GENESIS);
                let mutations: Vec<_> = (0..num_accounts)
                    .map(|_| {
                        let account_id = generate_account_id(&mut seed);
                        let commitment = generate_word(&mut seed);
                        (account_id, commitment)
                    })
                    .collect();
                tree.compute_and_apply_mutations(black_box(mutations)).unwrap();
            });
        });
    }

    group.finish();
}

criterion_group!(
    name = historical_account_tree;
    config = Criterion::default()
        .measurement_time(std::time::Duration::from_millis(1500))
        .warm_up_time(std::time::Duration::from_millis(100))
        .sample_size(10);
    targets = bench_vanilla_access,
        bench_vanilla_insertion,
        bench_historical_access,
        bench_insertion_with_history
);
criterion_main!(historical_account_tree);
