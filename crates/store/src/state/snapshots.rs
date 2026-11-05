//! Recent tree generations available to readers with an established SQLite snapshot.

use std::collections::VecDeque;
use std::num::NonZeroUsize;
use std::sync::Arc;

use arc_swap::ArcSwap;
use miden_protocol::block::BlockNumber;

use super::StateSnapshot;

/// Maximum number of retained tree generations, including the latest publication.
///
/// Four generations provide a few blocks of acquisition headroom while limiting retained state.
/// Each additional generation can keep roughly 8 MiB of account and nullifier tree caches alive
/// if both trees change between blocks, plus workload-dependent account history and forest
/// metadata. MMR chunks are shared between generations. Native `RocksDB` snapshots are small
/// handles, but retain older key versions, and cached generations also delay SQL history pruning.
const CAPACITY: NonZeroUsize = NonZeroUsize::new(4).unwrap();

/// A bounded history of immutable tree snapshots published by the single block writer.
///
/// Publication replaces the entire deque, so readers can load the latest snapshot or look up a
/// block without locking or communicating with the writer. Cloning a generation's `Arc` keeps it
/// alive after eviction. Loading the store after a restart initially retains only the loaded tip.
pub(crate) struct RecentSnapshots<T = StateSnapshot> {
    generations: ArcSwap<VecDeque<(BlockNumber, Arc<T>)>>,
}

impl<T> RecentSnapshots<T> {
    pub(in crate::state) fn new(block_num: BlockNumber, snapshot: Arc<T>) -> Self {
        Self {
            generations: ArcSwap::from_pointee(VecDeque::from([(block_num, snapshot)])),
        }
    }

    /// Returns the latest published generation.
    pub(crate) fn latest(&self) -> Arc<T> {
        Arc::clone(&self.generations.load().back().expect("snapshot history is nonempty").1)
    }

    /// Returns the retained generation at `block_num`, or `None` if it is unavailable.
    pub(crate) fn get(&self, block_num: BlockNumber) -> Option<Arc<T>> {
        self.generations
            .load()
            .iter()
            .find(|(height, _)| *height == block_num)
            .map(|(_, snapshot)| Arc::clone(snapshot))
    }

    /// Retains a new generation and evicts the oldest when the history reaches its limit.
    ///
    /// Returns the evicted generation so the writer can track readers that still hold it. Only the
    /// block writer publishes, and heights must increase. Concurrent lookups can finish using the
    /// old deque, and eviction never invalidates acquired readers.
    pub(in crate::state) fn push(
        &self,
        block_num: BlockNumber,
        snapshot: Arc<T>,
    ) -> Option<(BlockNumber, Arc<T>)> {
        let mut generations = VecDeque::clone(&self.generations.load());
        assert!(
            generations.back().is_none_or(|(height, _)| *height < block_num),
            "snapshot generations must be published in increasing block order",
        );
        let evicted = if generations.len() == CAPACITY.get() {
            generations.pop_front()
        } else {
            None
        };
        generations.push_back((block_num, snapshot));
        self.generations.store(Arc::new(generations));
        evicted
    }
}

/// An evicted tree generation that still has owners outside the retirement buffer.
#[derive(Debug, thiserror::Error)]
#[error("evicted snapshot at block {block_num} still has {references} external references")]
pub(in crate::state) struct SnapshotStillHeld {
    pub(in crate::state) block_num: BlockNumber,
    pub(in crate::state) references: usize,
}

/// Evicted generations awaiting release by readers.
///
/// The block writer owns this buffer and checks it after each publication. Unique snapshots are
/// dropped immediately; snapshots still shared with readers remain here until a later check.
/// Their strong references also remain visible to the legacy history-pruning tracker.
pub(in crate::state) struct RetiredSnapshots<T = StateSnapshot> {
    generations: VecDeque<(BlockNumber, Arc<T>)>,
}

impl<T> RetiredSnapshots<T> {
    pub(in crate::state) fn new() -> Self {
        Self { generations: VecDeque::new() }
    }

    /// Releases an evicted generation if it is unique, otherwise queues it for a later check.
    ///
    /// The pruning tracker holds weak references. `Arc::try_unwrap` permits those references,
    /// whereas `Arc::get_mut` would reject them even after every reader has released the snapshot.
    pub(in crate::state) fn push(&mut self, block_num: BlockNumber, snapshot: Arc<T>) {
        if let Err(snapshot) = Arc::try_unwrap(snapshot) {
            self.generations.push_back((block_num, snapshot));
        }
    }

    /// Releases unique generations and reports every generation that is still held elsewhere.
    ///
    /// The reported count excludes this buffer's reference. Readers can release or clone their
    /// references concurrently, so the count is an observation rather than a stable reader count.
    pub(in crate::state) fn reclaim(&mut self, mut report: impl FnMut(SnapshotStillHeld)) {
        for _ in 0..self.generations.len() {
            let (block_num, snapshot) =
                self.generations.pop_front().expect("retired generation exists");
            if let Err(snapshot) = Arc::try_unwrap(snapshot) {
                report(SnapshotStillHeld {
                    block_num,
                    references: Arc::strong_count(&snapshot) - 1,
                });
                self.generations.push_back((block_num, snapshot));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retains_recent_generations_and_reports_the_latest_height() {
        let history = RecentSnapshots::new(0.into(), Arc::new(0));
        assert_eq!(*history.latest(), 0);
        for height in 1..CAPACITY.get() as u32 {
            drop(history.push(height.into(), Arc::new(height)));
        }
        for height in 0..CAPACITY.get() as u32 {
            assert_eq!(*history.get(height.into()).unwrap(), height);
        }
        assert_eq!(*history.latest(), CAPACITY.get() as u32 - 1);
        assert!(history.get((CAPACITY.get() as u32).into()).is_none());
    }

    #[test]
    fn startup_retains_only_the_loaded_generation() {
        let history = RecentSnapshots::new(100.into(), Arc::new(100));
        assert_eq!(*history.latest(), 100);
        assert!(history.get(99.into()).is_none());
        assert!(history.get(101.into()).is_none());
        assert_eq!(*history.get(100.into()).unwrap(), 100);
    }

    #[test]
    fn pruning_follows_cached_generations_and_readers_after_eviction() {
        use crate::state::view::PublishedGenerations;

        let initial = Arc::new(0);
        let mut published = PublishedGenerations::new();
        published.record(0.into(), &initial);
        let history = RecentSnapshots::new(0.into(), initial);
        for height in 1..=CAPACITY.get() as u32 {
            let snapshot = Arc::new(height);
            published.record(height.into(), &snapshot);
            drop(history.push(height.into(), snapshot));
        }
        let tip = BlockNumber::from(CAPACITY.get() as u32);
        assert_eq!(published.advance(tip).prune_tip, BlockNumber::from(1));
        let reader = history.get(1.into()).unwrap();
        for height in CAPACITY.get() as u32 + 1..=2 * CAPACITY.get() as u32 {
            let snapshot = Arc::new(height);
            published.record(height.into(), &snapshot);
            drop(history.push(height.into(), snapshot));
        }
        let tip = BlockNumber::from(2 * CAPACITY.get() as u32);
        assert_eq!(published.advance(tip).prune_tip, BlockNumber::from(1));
        drop(reader);
        assert_eq!(published.advance(tip).prune_tip, BlockNumber::from(CAPACITY.get() as u32 + 1));
    }

    #[test]
    fn eviction_keeps_acquired_readers_alive_without_retaining_unbounded_history() {
        let initial = Arc::new(0);
        let weak = Arc::downgrade(&initial);
        let history = RecentSnapshots::new(0.into(), initial);
        let reader = history.get(0.into()).unwrap();
        for height in 1..=CAPACITY.get() as u32 {
            drop(history.push(height.into(), Arc::new(height)));
        }
        assert!(history.get(0.into()).is_none());
        assert_eq!(*history.latest(), CAPACITY.get() as u32);
        assert!(history.get(1.into()).is_some());
        assert_eq!(*reader, 0);
        assert!(weak.upgrade().is_some());
        drop(reader);
        assert!(weak.upgrade().is_none());
    }

    #[test]
    fn unheld_evicted_snapshot_is_released_immediately() {
        let snapshot = Arc::new(0);
        let weak = Arc::downgrade(&snapshot);
        let recent = RecentSnapshots::new(0.into(), snapshot);
        let mut retired = RetiredSnapshots::new();
        for height in 1..=CAPACITY.get() as u32 {
            if let Some((block_num, snapshot)) = recent.push(height.into(), Arc::new(height)) {
                retired.push(block_num, snapshot);
            }
        }
        assert!(weak.upgrade().is_none());
        let mut reported = Vec::new();
        retired.reclaim(|error| reported.push((error.block_num, error.references)));
        assert!(reported.is_empty());
    }

    #[test]
    fn held_generations_are_reported_each_time_and_released_after_readers_drop() {
        let first = Arc::new(0);
        let first_weak = Arc::downgrade(&first);
        let first_reader = Arc::clone(&first);
        let second = Arc::new(1);
        let second_weak = Arc::downgrade(&second);
        let second_readers = [Arc::clone(&second), Arc::clone(&second)];
        let mut retired = RetiredSnapshots::new();
        retired.push(0.into(), first);
        retired.push(1.into(), second);
        for _ in 0..2 {
            let mut reported = Vec::new();
            retired.reclaim(|error| reported.push((error.block_num, error.references)));
            assert_eq!(reported, vec![(BlockNumber::from(0), 1), (BlockNumber::from(1), 2)]);
        }
        drop(first_reader);
        let mut reported = Vec::new();
        retired.reclaim(|error| reported.push((error.block_num, error.references)));
        assert_eq!(reported, vec![(BlockNumber::from(1), 2)]);
        assert!(first_weak.upgrade().is_none());
        assert!(second_weak.upgrade().is_some());
        drop(second_readers);
        retired.reclaim(|_| panic!("released generations must not be reported"));
        assert!(second_weak.upgrade().is_none());
    }
}
