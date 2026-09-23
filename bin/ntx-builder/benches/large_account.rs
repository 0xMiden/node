//! Benchmark: building a network transaction against a very large account.
//!
//! The `ntx-builder` keeps the native network `Account` fully resident in memory for the lifetime of
//! an actor. For an account with a large storage map (e.g. a million entries) that could become
//! untenable. This benchmark measures the costs so we can decide whether lazy/partial native-account
//! loading is worth implementing.

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::BTreeSet;
use std::hint::black_box;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use miden_protocol::Word;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountType,
    PartialAccount,
    StorageMap,
    StorageMapKey,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::asset::FungibleAsset;
use miden_protocol::testing::account_id::AccountIdBuilder;
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_standards::account::auth::AuthNetworkAccount;
use miden_standards::account::fees::FeePolicyManager;
use miden_standards::note::{NetworkAccountTarget, NoteExecutionHint};
use miden_standards::testing::account_component::MockAccountComponent;
use miden_standards::testing::note::NoteBuilder;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;

// COUNTING GLOBAL ALLOCATOR
// ================================================================================================

/// A thin wrapper around the [`System`] allocator that tracks the live and peak number of bytes
/// allocated. It lets us measure the real resident heap footprint of an [`Account`] without relying
/// on platform-specific RSS probing.
///
/// `realloc`/`alloc_zeroed` are intentionally not overridden so the trait's default
/// implementations route through `alloc`/`dealloc`, keeping the byte accounting consistent.
struct CountingAllocator;

/// Currently live allocated bytes.
static LIVE: AtomicUsize = AtomicUsize::new(0);
/// High-water mark of live allocated bytes since the last [`reset_peak`].
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            let live = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(live, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

/// Returns the currently live allocated bytes.
fn live_bytes() -> usize {
    LIVE.load(Ordering::Relaxed)
}

/// Returns the peak live bytes recorded since the last [`reset_peak`].
fn peak_bytes() -> usize {
    PEAK.load(Ordering::Relaxed)
}

/// Resets the peak counter to the current live value, so the next measurement window starts fresh.
fn reset_peak() {
    PEAK.store(LIVE.load(Ordering::Relaxed), Ordering::Relaxed);
}

// ACCOUNT GENERATION
// ================================================================================================

/// Builds an [`AuthNetworkAccount`] auth component with a single-entry note allowlist.
fn network_auth_component() -> AuthNetworkAccount {
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    let sender = AccountIdBuilder::new()
        .account_type(AccountType::Private)
        .build_with_rng(&mut rng);
    let target_id = AccountIdBuilder::new()
        .account_type(AccountType::Public)
        .build_with_seed([9u8; 32]);
    let target = NetworkAccountTarget::new(target_id, NoteExecutionHint::Always)
        .expect("network account should be a valid target");
    let note = NoteBuilder::new(sender, rng)
        .attachment(target)
        .build()
        .expect("note should build");
    let root = note.script().root();

    // Nothing here executes a transaction, so the mock manager's empty fee schedule is enough: it
    // only has to make the component constructible and install the three fee-policy slots.
    AuthNetworkAccount::new(
        [root].into_iter().collect::<BTreeSet<_>>(),
        FeePolicyManager::mock(FungibleAsset::mock_issuer()),
    )
    .expect("non-empty allowlist should construct")
}

/// Builds a single storage slot holding a map with `num_entries` entries, keyed `[i, 0, 0, 0]`.
fn large_map_slot(slot_idx: u32, num_entries: u32) -> StorageSlot {
    let entries: Vec<(StorageMapKey, Word)> = (0..num_entries)
        .map(|i| (StorageMapKey::from_index(i), Word::from([i, 0, 0, 1])))
        .collect();

    let name = StorageSlotName::new(format!("miden::bench::map_slot_{slot_idx}"))
        .expect("slot name should be valid");
    StorageSlot::with_map(name, StorageMap::with_entries(entries).expect("valid map"))
}

/// Synthesizes a network [`Account`] with `num_maps` storage maps, each holding `entries_per_map`
/// entries. Mirrors the `ntx-builder`'s network-account recipe (`MockAccountComponent` +
/// `AuthNetworkAccount`), extended with populated map slots.
fn build_large_network_account(num_maps: u32, entries_per_map: u32) -> Account {
    let slots: Vec<StorageSlot> =
        (0..num_maps).map(|m| large_map_slot(m, entries_per_map)).collect();

    AccountBuilder::new([0u8; 32])
        .account_type(AccountType::Public)
        .with_component(MockAccountComponent::with_slots(slots))
        .with_components(network_auth_component())
        .build_existing()
        .expect("account should build")
}

// TIMING
// ================================================================================================

/// Runs `op` `iters` times and returns the median wall-clock duration. The result of each call is
/// passed through [`black_box`] so the work is not optimized away.
fn median_time<T>(iters: usize, mut op: impl FnMut() -> T) -> Duration {
    let mut samples: Vec<Duration> = Vec::with_capacity(iters);
    for _ in 0..iters {
        let start = Instant::now();
        let out = op();
        let elapsed = start.elapsed();
        black_box(out);
        samples.push(elapsed);
    }
    samples.sort_unstable();
    samples[samples.len() / 2]
}

// REPORTING
// ================================================================================================

/// One row of the results table.
struct Row {
    entries: u32,
    resident_bytes: usize,
    build_peak_bytes: usize,
    serialized_bytes: usize,
    deserialize: Duration,
    clone: Duration,
    partial_from: Duration,
    serialize: Duration,
}

/// Measures all metrics for a single map size. `num_maps` maps each hold `entries_per_map` entries.
fn measure(num_maps: u32, entries_per_map: u32) -> Row {
    let iters = if entries_per_map >= 500_000 { 3 } else { 11 };

    // Resident + peak footprint of the built account. The transient entry vectors are freed inside
    // `build_large_network_account`, so `live_after - live_before` approximates the account's own
    // resident heap, while the peak captures the construction high-water mark.
    let live_before = live_bytes();
    reset_peak();
    let account = build_large_network_account(num_maps, entries_per_map);
    let resident_bytes = live_bytes().saturating_sub(live_before);
    let build_peak_bytes = peak_bytes().saturating_sub(live_before);

    // Serialize once for the size figure and to feed the deserialize benchmark.
    let bytes = account.to_bytes();
    let serialized_bytes = bytes.len();

    let deserialize = median_time(iters, || {
        Account::read_from_bytes(&bytes).expect("account should deserialize")
    });
    let clone = median_time(iters, || account.clone());
    let partial_from = median_time(iters, || PartialAccount::from(&account));
    let serialize = median_time(iters, || account.to_bytes());

    Row {
        entries: entries_per_map,
        resident_bytes,
        build_peak_bytes,
        serialized_bytes,
        deserialize,
        clone,
        partial_from,
        serialize,
    }
}

/// Formats a byte count in the largest unit that keeps it readable, with one decimal. Integer math
/// throughout to avoid lossy casts. A fixed `MiB` unit would print the smaller cases as `0.0 MiB`.
fn bytes(bytes: usize) -> String {
    const UNITS: [(usize, &str); 4] =
        [(1 << 30, "GiB"), (1 << 20, "MiB"), (1 << 10, "KiB"), (1, "B")];

    for (scale, unit) in UNITS {
        if bytes >= scale {
            if scale == 1 {
                return format!("{bytes} {unit}");
            }
            return format!("{}.{} {unit}", bytes / scale, (bytes % scale) * 10 / scale);
        }
    }
    "0 B".to_string()
}

/// Formats a duration as milliseconds with three decimals.
fn ms(d: Duration) -> String {
    format!("{:.3} ms", d.as_secs_f64() * 1_000.0)
}

fn print_table(rows: &[Row]) {
    println!(
        "\n{:>10}  {:>12}  {:>12}  {:>12}  {:>12}  {:>12}  {:>14}  {:>12}",
        "entries",
        "resident",
        "build_peak",
        "serialized",
        "deserialize",
        "clone",
        "partial_from",
        "serialize",
    );
    println!("{}", "-".repeat(112));
    for r in rows {
        println!(
            "{:>10}  {:>12}  {:>12}  {:>12}  {:>12}  {:>12}  {:>14}  {:>12}",
            r.entries,
            bytes(r.resident_bytes),
            bytes(r.build_peak_bytes),
            bytes(r.serialized_bytes),
            ms(r.deserialize),
            ms(r.clone),
            ms(r.partial_from),
            ms(r.serialize),
        );
    }
}

/// Summarises the largest case measured, and where each figure is paid.
///
/// Deliberately states no threshold and passes no judgement: what counts as too much depends on the
/// deployment — the memory available to the process, how many actors it runs concurrently, and how
/// long a reload may take before the submission it is reloading for expires. None of that is known
/// here, so this reports sizes and leaves the conclusion to the reader.
fn print_summary(rows: &[Row]) {
    let Some(largest) = rows.iter().max_by_key(|r| r.resident_bytes) else {
        return;
    };
    let entries = usize::try_from(largest.entries.max(1)).unwrap_or(1);

    println!("\nSummary");
    println!("{}", "-".repeat(112));
    println!(
        "Largest case measured: {} entries -> {} resident, {} peak while building, {} on disk, {} \
         to load.",
        largest.entries,
        bytes(largest.resident_bytes),
        bytes(largest.build_peak_bytes),
        bytes(largest.serialized_bytes),
        ms(largest.deserialize),
    );
    println!(
        "That is {}x the on-disk size held in memory, or {} of heap per {} on disk, per entry.",
        largest.resident_bytes / largest.serialized_bytes.max(1),
        bytes(largest.resident_bytes / entries),
        bytes(largest.serialized_bytes / entries),
    );
    println!(
        "Where each is paid: `resident` for the actor's whole lifetime, `build_peak` transiently \
         while loading, `deserialize` on actor start and on every reload after a submission expires."
    );
    println!(
        "Flat in map size: {} to derive a PartialAccount (minimal partial storage), which also \
         bounds the submitted TransactionInputs.",
        ms(largest.partial_from),
    );
}

// ENTRY POINT
// ================================================================================================

fn main() {
    // Sizes are the number of entries per storage map. One storage map is used per account. 1M is
    // deliberately not a default: it needs several GiB of RAM. Pass it explicitly.
    let default_sizes: Vec<u32> = vec![1_000, 10_000, 100_000];
    // `cargo bench` passes `--bench` to a `harness = false` binary; non-numeric args are ignored.
    let sizes: Vec<u32> = std::env::args()
        .skip(1)
        .filter_map(|a| a.parse::<u32>().ok())
        .collect::<Vec<_>>();
    let sizes = if sizes.is_empty() { default_sizes } else { sizes };

    // Keep a stable account type digest in the output so the reader knows what was measured.
    println!("ntx-builder large-account benchmark (issue #2363)");
    println!("account: 1 storage map, MockAccountComponent + AuthNetworkAccount, type = Public");

    // Warm up before measuring anything. The first account build lazily allocates the assembler's
    // MAST forests and other one-time statics, which the allocator counts against whichever row
    // triggers them — enough to dominate the smallest row's `resident` figure outright.
    println!("warming up...");
    drop(black_box(build_large_network_account(1, 1)));

    let mut rows = Vec::with_capacity(sizes.len());
    for &n in &sizes {
        println!("building account with {n} map entries...");
        rows.push(measure(1, n));
    }

    print_table(&rows);
    print_summary(&rows);
}
