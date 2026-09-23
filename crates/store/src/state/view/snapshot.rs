//! In-memory snapshot machinery for lock-free reads.
//!
//! Readers access the store's tree state through immutable [`StateSnapshot`] snapshots published
//! by the block writer after each committed block. [`SnapshotGuard`] tracks how many snapshot
//! generations are pinned by readers, since each generation pins a `RocksDB` snapshot. The writer
//! additionally remembers each published generation in [`PublishedGenerations`], whose oldest
//! still-pinned height feeds snapshot-aware history pruning, since SQLite reads have no
//! point-in-time protection equivalent to the `RocksDB` snapshots backing the trees.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, Weak};
use std::time::{Duration, Instant};

use miden_node_tracing::{debug, warn};
use miden_protocol::block::nullifier_tree::NullifierTree;
use miden_protocol::block::{BlockNumber, Blockchain};
use miden_protocol::crypto::merkle::smt::LargeSmt;

use crate::COMPONENT;
use crate::account_state_forest::{
    AccountStateForest,
    AccountStateForestBackendReader,
    HISTORICAL_BLOCK_RETENTION,
};
use crate::accounts::AccountTreeWithHistory;
use crate::state::loader::TreeStorageReader;

/// Time held past supersession above which [`SnapshotGuard`] logs a warning on release.
///
/// Readers are expected to be request-scoped, so a superseded generation outliving several block
/// intervals indicates a slow or leaked reader pinning a `RocksDB` snapshot (see
/// [`SnapshotGuard`]). The clock starts at supersession rather than creation: the latest
/// generation is always pinned by the published pointer, so time spent as the current generation
/// (idle chains, shutdown) says nothing about reader behaviour.
const SNAPSHOT_SUPERSEDED_WARN_THRESHOLD: Duration = Duration::from_secs(10);

/// Number of live snapshot generations above which the block writer logs a warning after
/// publishing a new snapshot.
///
/// Steady state is 1-2 generations: the just-published snapshot plus predecessors briefly pinned
/// by in-flight requests. A sustained higher count means slow or leaked readers are holding old
/// generations alive (see [`SnapshotGuard`]).
pub(in crate::state) const SNAPSHOTS_LIVE_WARN_THRESHOLD: u64 = 4;

/// Upper bound on how far the snapshot-aware pruning tip may lag the chain tip.
///
/// History pruning keys off the oldest live snapshot generation (see
/// [`PublishedGenerations::prune_tip`]), so a leaked or pathologically slow reader would
/// otherwise stall pruning indefinitely. Beyond this
/// many blocks of lag the writer prunes anyway, accepting the historical-read race for that reader
/// (which the snapshot-lifetime warnings have long since reported). One full retention window, so
/// worst-case retained history is bounded at twice the window.
const SNAPSHOT_PRUNE_LAG_CAP: u32 = HISTORICAL_BLOCK_RETENTION;

// PUBLISHED GENERATIONS
// ================================================================================================

/// The writer's log of published snapshot generations, used to derive the oldest height still
/// pinned by a reader.
///
/// Owned exclusively by the writer — no locks or shared state. Liveness is not tracked
/// separately: a [`Weak`] per generation asks the snapshot's own [`Arc`] refcount, which is the
/// ground truth for "some reader can still see this height". Dead and no-longer-relevant entries
/// are discarded on each [`Self::prune_tip`] call (once per applied block), which bounds the
/// deque to roughly [`SNAPSHOT_PRUNE_LAG_CAP`] entries even when a reader leaks its snapshot.
///
/// Generic over the pinned type for testability; the writer uses `T = StateSnapshot`.
pub(in crate::state) struct PublishedGenerations<T = StateSnapshot> {
    /// Published generations in ascending height order.
    entries: VecDeque<(BlockNumber, Weak<T>)>,
}

impl<T> PublishedGenerations<T> {
    pub(in crate::state) fn new() -> Self {
        Self { entries: VecDeque::new() }
    }

    /// Records a newly published generation. Heights must be recorded in ascending order.
    pub(in crate::state) fn record(&mut self, height: BlockNumber, pinned: &Arc<T>) {
        debug_assert!(
            self.entries.back().is_none_or(|(back, _)| *back < height),
            "generation {height} published out of order",
        );
        self.entries.push_back((height, Arc::downgrade(pinned)));
    }

    /// Returns the effective chain tip for history pruning.
    ///
    /// The store's SQLite reads are scoped only by an upper block bound, with no point-in-time
    /// protection equivalent to the `RocksDB` snapshots backing the trees. Pruning therefore
    /// treats the oldest still-pinned generation as the tip: a generation pinned at height `H`
    /// keeps the same retention window it had when `H` was the tip, and pruning simply lags until
    /// it is released. The lag is capped at [`SNAPSHOT_PRUNE_LAG_CAP`] blocks so a leaked reader
    /// cannot stall pruning indefinitely: entries below the cap's floor are discarded despite
    /// still being pinned, as are entries that are no longer pinned.
    pub(in crate::state) fn prune_tip(&mut self, chain_tip: BlockNumber) -> BlockNumber {
        let lag_floor = chain_tip.as_u32().saturating_sub(SNAPSHOT_PRUNE_LAG_CAP);
        while let Some((height, pinned)) = self.entries.front() {
            // Drop entries below the lag floor or that are no longer pinned.
            if height.as_u32() < lag_floor || pinned.strong_count() == 0 {
                self.entries.pop_front();
            } else {
                break;
            }
        }
        // Return the prune tip, which is the oldest pinned generation or the chain tip.
        self.entries.front().map_or(chain_tip, |(height, _)| (*height).min(chain_tip))
    }
}

// SNAPSHOT GUARD
// ================================================================================================

/// RAII member of [`StateSnapshot`] that tracks the number of live snapshot generations.
///
/// [`StateSnapshot`] is dropped exactly when the last [`Arc`] reference to it is released, so the
/// shared counter reports how many distinct snapshot generations are currently pinned by readers.
/// A sustained count above 1-2 means slow readers are holding old generations alive. Each
/// generation pins a `RocksDB` snapshot, which delays garbage collection of superseded key
/// versions during compaction (compaction itself keeps running); the retained garbage grows with
/// write churn for as long as the snapshot is held and is reclaimed once it is released. A held
/// generation also holds back SQLite history pruning (see [`PublishedGenerations::prune_tip`]).
///
/// Readers are expected to be request-scoped, so a superseded generation should be released well
/// within a block interval. Outliving supersession by more than
/// [`SNAPSHOT_SUPERSEDED_WARN_THRESHOLD`] is logged at warn level; a generation that is never
/// superseded (the latest at shutdown) is released silently regardless of age.
pub(in crate::state) struct SnapshotGuard {
    live: Arc<AtomicUsize>,
    created_at: Instant,
    /// Set by the writer when a newer generation replaces this one as the published snapshot.
    superseded_at: OnceLock<Instant>,
    block_num: BlockNumber,
}

impl SnapshotGuard {
    pub(in crate::state) fn new(live: Arc<AtomicUsize>, block_num: BlockNumber) -> Self {
        live.fetch_add(1, Ordering::Relaxed);
        Self {
            live,
            created_at: Instant::now(),
            superseded_at: OnceLock::new(),
            block_num,
        }
    }

    /// Marks this generation as superseded by a newer published snapshot, starting the clock
    /// against which slow readers are measured. Only the first call takes effect.
    pub(in crate::state) fn mark_superseded(&self) {
        let _ = self.superseded_at.set(Instant::now());
    }
}

impl Drop for SnapshotGuard {
    fn drop(&mut self) {
        let remaining = self.live.fetch_sub(1, Ordering::Relaxed) - 1;
        let lifetime_ms = u64::try_from(self.created_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        let block_num = self.block_num.as_u32();
        let superseded_for = self.superseded_at.get().map(Instant::elapsed);
        if let Some(superseded_for) =
            superseded_for.filter(|held| *held > SNAPSHOT_SUPERSEDED_WARN_THRESHOLD)
        {
            let superseded_for_ms = u64::try_from(superseded_for.as_millis()).unwrap_or(u64::MAX);
            warn!(
                target: COMPONENT,
                "State snapshot held for excessive time after supersession",
                block.number = block_num,
                snapshot.lifetime_ms = lifetime_ms,
                snapshot.superseded_for_ms = superseded_for_ms,
                snapshots.live = remaining
            );
        } else {
            debug!(
                target: COMPONENT,
                "State snapshot released",
                block.number = block_num,
                snapshot.lifetime_ms = lifetime_ms,
                snapshots.live = remaining
            );
        }
    }
}

// STATE SNAPSHOT
// ================================================================================================

/// Immutable snapshot of the store's tree state published after each committed block.
///
/// The trees are backed by read-only snapshot storage ([`TreeStorageReader`] /
/// [`AccountStateForestBackendReader`]), so any number of readers can access the data concurrently
/// without holding a lock and without blocking the writer.
///
/// The writer and lifecycle can *construct* snapshots via [`Self::new`], but the fields are only
/// readable within the view module tree: every read outside it must go through
/// [`StateView`](super::StateView).
pub(in crate::state) struct StateSnapshot {
    pub(super) nullifier_tree: NullifierTree<LargeSmt<TreeStorageReader>>,
    pub(super) blockchain: Blockchain,
    pub(super) account_tree: AccountTreeWithHistory<TreeStorageReader>,
    pub(super) forest: AccountStateForest<AccountStateForestBackendReader>,
    /// Keeps the live-snapshot count accurate; see [`SnapshotGuard`].
    guard: SnapshotGuard,
}

impl StateSnapshot {
    /// Assembles a snapshot from reader views of the trees and the guard tracking its generation.
    pub(in crate::state) fn new(
        nullifier_tree: NullifierTree<LargeSmt<TreeStorageReader>>,
        blockchain: Blockchain,
        account_tree: AccountTreeWithHistory<TreeStorageReader>,
        forest: AccountStateForest<AccountStateForestBackendReader>,
        guard: SnapshotGuard,
    ) -> Self {
        Self {
            nullifier_tree,
            blockchain,
            account_tree,
            forest,
            guard,
        }
    }

    /// Marks this snapshot as superseded by a newer published generation; see
    /// [`SnapshotGuard::mark_superseded`].
    pub(in crate::state) fn mark_superseded(&self) {
        self.guard.mark_superseded();
    }

    /// Returns the latest block number.
    pub(in crate::state) fn latest_block_num(&self) -> BlockNumber {
        self.blockchain
            .chain_tip()
            .expect("chain should always have at least the genesis block")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prune_tip_tracks_oldest_pinned_height_across_out_of_order_drops() {
        let mut published = PublishedGenerations::<u32>::new();
        let tip = BlockNumber::from(100);

        // No live generations: prune at the tip.
        assert_eq!(published.prune_tip(tip), tip);

        let gen_97 = Arc::new(97);
        let gen_98 = Arc::new(98);
        let gen_99 = Arc::new(99);
        published.record(BlockNumber::from(97), &gen_97);
        published.record(BlockNumber::from(98), &gen_98);
        published.record(BlockNumber::from(99), &gen_99);
        assert_eq!(published.prune_tip(tip), BlockNumber::from(97));

        // Dropping a middle generation leaves the oldest unchanged.
        drop(gen_98);
        assert_eq!(published.prune_tip(tip), BlockNumber::from(97));

        drop(gen_97);
        assert_eq!(published.prune_tip(tip), BlockNumber::from(99));

        // A pinned generation never advances pruning past the tip.
        assert_eq!(published.prune_tip(BlockNumber::from(98)), BlockNumber::from(98));

        drop(gen_99);
        assert_eq!(published.prune_tip(tip), tip);
    }

    #[test]
    fn prune_tip_discards_leaked_entries_below_the_lag_floor() {
        let mut published = PublishedGenerations::<u32>::new();
        let leaked = Arc::new(1);
        published.record(BlockNumber::from(1), &leaked);

        // While the leaked generation is within the lag cap it holds pruning back; near genesis the
        // lag floor saturates to zero.
        let tip = BlockNumber::from(SNAPSHOT_PRUNE_LAG_CAP);
        assert_eq!(published.prune_tip(tip), BlockNumber::from(1));

        // Once the tip advances past the cap it is discarded despite still being pinned, and no
        // longer holds pruning back.
        let tip = BlockNumber::from(SNAPSHOT_PRUNE_LAG_CAP + 2);
        assert_eq!(published.prune_tip(tip), tip);
    }
}
