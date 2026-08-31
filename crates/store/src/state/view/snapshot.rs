//! In-memory snapshot machinery for lock-free reads.
//!
//! Readers access the store's tree state through immutable [`StateSnapshot`] snapshots published
//! by the block writer after each committed block. The writer remembers each published generation
//! in [`PublishedGenerations`]. The oldest still-pinned height feeds snapshot-aware history
//! pruning, since SQLite reads have no point-in-time protection equivalent to the `RocksDB`
//! snapshots backing the trees. The same log supplies the per-block snapshot span fields that
//! expose slow or leaked readers.
//!
//! Everything here operates on whole generations. Readers acquire a snapshot through
//! [`StateView`](super::StateView), the request-scoped handle.

use std::collections::VecDeque;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use miden_protocol::block::nullifier_tree::NullifierTree;
use miden_protocol::block::{BlockNumber, Blockchain};
use miden_protocol::crypto::merkle::smt::LargeSmt;

use crate::account_state_forest::{
    AccountStateForest,
    AccountStateForestBackendReader,
    HISTORICAL_BLOCK_RETENTION,
};
use crate::accounts::AccountTreeWithHistory;
use crate::state::loader::TreeStorageReader;

/// Upper bound on how far the snapshot-aware pruning tip may lag the chain tip.
///
/// History pruning keys off the oldest live snapshot generation (see
/// [`PublishedGenerations::advance`]), so a leaked or pathologically slow reader would
/// otherwise stall pruning indefinitely. Beyond this many blocks of lag the writer prunes anyway
/// and accepts the historical-read race for that reader. The `snapshots.lag_blocks` span field
/// reports the lag on each applied block (see [`GenerationsStatus::oldest_pinned`]). The cap is
/// one full retention window, so worst-case retained history is bounded at twice the window.
const SNAPSHOT_PRUNE_LAG_CAP: u32 = HISTORICAL_BLOCK_RETENTION;

// PUBLISHED GENERATIONS
// ================================================================================================

/// The writer's log of published snapshot generations, used to derive the oldest height still
/// pinned by a reader.
///
/// Owned exclusively by the writer — no locks or shared state. Liveness is not tracked
/// separately: a [`Weak`] per generation asks the snapshot's own [`Arc`] refcount, which is the
/// ground truth for "some reader can still see this height". Dead entries are discarded on each
/// [`Self::advance`] call (once per applied block); pinned entries are kept regardless of age so
/// the true oldest pinned height stays observable, which bounds the deque to one entry per live
/// snapshot generation (each entry is small next to the pinned snapshot itself).
///
/// Generic over the pinned type for testability; the writer uses `T = StateSnapshot`.
pub(in crate::state) struct PublishedGenerations<T = StateSnapshot> {
    /// Published generations in ascending height order.
    entries: VecDeque<Generation<T>>,
}

/// One published snapshot generation tracked by [`PublishedGenerations`].
struct Generation<T> {
    height: BlockNumber,
    /// The time when a successor generation was published. `None` while this is the latest
    /// generation.
    ///
    /// [`PublishedGenerations::record`] sets this field on the previous back entry. Reader
    /// behaviour is measured from supersession, not from publication: the published pointer
    /// always pins the latest generation, so time spent as the latest generation gives no
    /// information about readers.
    superseded_at: Option<Instant>,
    pinned: Weak<T>,
}

impl<T> PublishedGenerations<T> {
    pub(in crate::state) fn new() -> Self {
        Self { entries: VecDeque::new() }
    }

    /// Records a newly published generation and marks the previous latest generation as superseded.
    /// Heights must be recorded in ascending order.
    pub(in crate::state) fn record(&mut self, height: BlockNumber, pinned: &Arc<T>) {
        debug_assert!(
            self.entries.back().is_none_or(|back| back.height < height),
            "generation {height} published out of order",
        );
        // The new generation supersedes the previous back entry.
        if let Some(previous) = self.entries.back_mut() {
            previous.superseded_at = Some(Instant::now());
        }
        self.entries.push_back(Generation {
            height,
            superseded_at: None,
            pinned: Arc::downgrade(pinned),
        });
    }

    /// Returns the number of recorded generations.
    ///
    /// Only [`Self::advance`] discards dead generations, so the count is exact directly after
    /// `advance` and is an upper bound on the live count between calls.
    pub(in crate::state) fn live(&self) -> usize {
        self.entries.len()
    }

    /// Discards generations no longer pinned by any reader and reports on those that remain.
    ///
    /// The prune tip is the effective chain tip for history pruning. The store's SQLite reads are
    /// scoped only by an upper block bound, with no point-in-time protection equivalent to the
    /// `RocksDB` snapshots backing the trees. Pruning therefore treats the oldest still-pinned
    /// generation as the tip: a generation pinned at height `H` keeps the same retention window it
    /// had when `H` was the tip, and pruning simply lags until it is released. The lag is capped
    /// at [`SNAPSHOT_PRUNE_LAG_CAP`] blocks so a leaked reader cannot stall pruning indefinitely:
    /// generations below the cap's floor no longer hold pruning back, but stay recorded so
    /// [`GenerationsStatus::oldest_pinned`] keeps reporting them for as long as they are pinned.
    pub(in crate::state) fn advance(&mut self, chain_tip: BlockNumber) -> GenerationsStatus {
        self.entries.retain(|generation| generation.pinned.strong_count() > 0);
        let oldest = self.entries.front();
        let oldest_pinned = oldest.map(|generation| generation.height);
        let oldest_superseded_for =
            oldest.and_then(|generation| generation.superseded_at).map(|at| at.elapsed());
        // The prune tip is the oldest pinned generation within the lag cap, or the chain tip.
        let lag_floor = chain_tip.as_u32().saturating_sub(SNAPSHOT_PRUNE_LAG_CAP);
        let prune_tip = self
            .entries
            .iter()
            .map(|generation| generation.height)
            .find(|height| height.as_u32() >= lag_floor)
            .map_or(chain_tip, |height| height.min(chain_tip));
        GenerationsStatus {
            prune_tip,
            oldest_pinned,
            oldest_superseded_for,
        }
    }
}

/// Per-block report on the still-pinned snapshot generations; see
/// [`PublishedGenerations::advance`].
pub(in crate::state) struct GenerationsStatus {
    /// The effective chain tip for history pruning: the oldest still-pinned generation within
    /// [`SNAPSHOT_PRUNE_LAG_CAP`], or the chain tip when none is pinned.
    pub(in crate::state) prune_tip: BlockNumber,
    /// The oldest generation still pinned by any reader, regardless of the lag cap. `None` when no
    /// generation is pinned.
    pub(in crate::state) oldest_pinned: Option<BlockNumber>,
    /// The time since the oldest pinned generation was superseded. `None` when that generation is
    /// still the latest generation, or when no generation is pinned. In steady state the value is
    /// `None` or much smaller than one block interval. A value that grows across blocks means a
    /// slow or leaked reader pins an old generation.
    pub(in crate::state) oldest_superseded_for: Option<Duration>,
}

// STATE SNAPSHOT
// ================================================================================================

/// Immutable snapshot of the store's tree state published after each committed block.
///
/// The trees are backed by read-only snapshot storage ([`TreeStorageReader`] /
/// [`AccountStateForestBackendReader`]), so any number of readers can access the data concurrently
/// without holding a lock and without blocking the writer.
///
/// A pinned snapshot pins the `RocksDB` snapshots that back the trees. A pinned `RocksDB`
/// snapshot delays garbage collection of superseded key versions during compaction; compaction
/// itself continues. A pinned snapshot also holds back SQLite history pruning (see
/// [`PublishedGenerations::advance`]).
///
/// The writer and lifecycle can *construct* snapshots via [`Self::new`], but the fields are only
/// readable within the view module tree: every read outside it must go through
/// [`StateView`](super::StateView).
pub(in crate::state) struct StateSnapshot {
    pub(super) nullifier_tree: NullifierTree<LargeSmt<TreeStorageReader>>,
    pub(super) blockchain: Blockchain,
    pub(super) account_tree: AccountTreeWithHistory<TreeStorageReader>,
    pub(super) forest: AccountStateForest<AccountStateForestBackendReader>,
}

impl StateSnapshot {
    /// Assembles a snapshot from reader views of the trees.
    pub(in crate::state) fn new(
        nullifier_tree: NullifierTree<LargeSmt<TreeStorageReader>>,
        blockchain: Blockchain,
        account_tree: AccountTreeWithHistory<TreeStorageReader>,
        forest: AccountStateForest<AccountStateForestBackendReader>,
    ) -> Self {
        Self {
            nullifier_tree,
            blockchain,
            account_tree,
            forest,
        }
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
    fn advance_tracks_oldest_pinned_height_across_out_of_order_drops() {
        let mut published = PublishedGenerations::<u32>::new();
        let tip = BlockNumber::from(100);

        // No live generations: prune at the tip.
        let status = published.advance(tip);
        assert_eq!(status.prune_tip, tip);
        assert_eq!(status.oldest_pinned, None);

        let gen_97 = Arc::new(97);
        let gen_98 = Arc::new(98);
        let gen_99 = Arc::new(99);
        published.record(BlockNumber::from(97), &gen_97);
        published.record(BlockNumber::from(98), &gen_98);
        published.record(BlockNumber::from(99), &gen_99);
        let status = published.advance(tip);
        assert_eq!(status.prune_tip, BlockNumber::from(97));
        assert_eq!(status.oldest_pinned, Some(BlockNumber::from(97)));
        assert_eq!(published.live(), 3);
        // Recording generation 98 superseded generation 97.
        assert!(status.oldest_superseded_for.is_some());

        // Dropping a middle generation leaves the oldest unchanged.
        drop(gen_98);
        assert_eq!(published.advance(tip).prune_tip, BlockNumber::from(97));

        drop(gen_97);
        let status = published.advance(tip);
        assert_eq!(status.prune_tip, BlockNumber::from(99));
        assert_eq!(published.live(), 1);
        // Generation 99 is the latest generation and is not superseded.
        assert!(status.oldest_superseded_for.is_none());

        // A pinned generation never advances pruning past the tip.
        assert_eq!(published.advance(BlockNumber::from(98)).prune_tip, BlockNumber::from(98));

        drop(gen_99);
        let status = published.advance(tip);
        assert_eq!(status.prune_tip, tip);
        assert_eq!(status.oldest_pinned, None);
    }

    #[test]
    fn advance_caps_prune_lag_but_keeps_reporting_the_leaked_oldest() {
        let mut published = PublishedGenerations::<u32>::new();
        let leaked = Arc::new(1);
        published.record(BlockNumber::from(1), &leaked);

        // While the leaked generation is within the lag cap it holds pruning back; near genesis the
        // lag floor saturates to zero.
        let tip = BlockNumber::from(SNAPSHOT_PRUNE_LAG_CAP);
        let status = published.advance(tip);
        assert_eq!(status.prune_tip, BlockNumber::from(1));
        assert_eq!(status.oldest_pinned, Some(BlockNumber::from(1)));
        // No successor generation was recorded, so the leaked generation is not superseded.
        assert!(status.oldest_superseded_for.is_none());

        // Once the tip advances past the cap it no longer holds pruning back, but is still reported
        // as the oldest pinned generation for as long as it is pinned.
        let tip = BlockNumber::from(SNAPSHOT_PRUNE_LAG_CAP + 2);
        let status = published.advance(tip);
        assert_eq!(status.prune_tip, tip);
        assert_eq!(status.oldest_pinned, Some(BlockNumber::from(1)));

        // A newer pinned generation above the floor becomes the prune tip while the leaked one
        // still drives the reported lag.
        let gen_recent = Arc::new(2);
        let recent_height = BlockNumber::from(SNAPSHOT_PRUNE_LAG_CAP + 1);
        published.record(recent_height, &gen_recent);
        let status = published.advance(tip);
        assert_eq!(status.prune_tip, recent_height);
        assert_eq!(status.oldest_pinned, Some(BlockNumber::from(1)));
        // Recording the newer generation superseded the leaked generation.
        assert!(status.oldest_superseded_for.is_some());

        drop(leaked);
        let status = published.advance(tip);
        assert_eq!(status.oldest_pinned, Some(recent_height));
    }
}
