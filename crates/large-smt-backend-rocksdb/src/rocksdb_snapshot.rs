use alloc::boxed::Box;
use alloc::vec::Vec;
use std::mem::ManuallyDrop;
use std::sync::Arc;

use miden_crypto::merkle::NodeIndex;
use miden_crypto::merkle::smt::{InnerNode, SmtLeaf, Subtree};
use rocksdb::{DB, IteratorMode, ReadOptions};

use super::{SmtStorageReader, StorageError};
use crate::Word;
use crate::helpers::{
    bucket_by_depth,
    map_rocksdb_err,
    read_count,
    read_depth24_entries,
    read_leaf,
    read_leaves,
    read_subtree,
    read_subtree_batch,
};
use crate::rocksdb::{
    DEPTH_24_CF,
    ENTRY_COUNT_KEY,
    IN_MEMORY_DEPTH,
    LEAF_COUNT_KEY,
    LEAVES_CF,
    METADATA_CF,
    RocksDbDirectLeafIterator,
    RocksDbStorage,
    RocksDbSubtreeIterator,
    SUBTREE_24_CF,
    SUBTREE_32_CF,
    SUBTREE_40_CF,
    SUBTREE_48_CF,
    SUBTREE_56_CF,
    SUBTREE_DEPTHS,
    cf_for_depth,
};

// SNAPSHOT STORAGE
// --------------------------------------------------------------------------------------------

/// Inner state shared by all clones of a snapshot storage.
///
/// This struct pairs a RocksDB snapshot with an `Arc<DB>` to ensure the database
/// lives for as long as the snapshot that references it.
///
/// # Safety
///
/// `snapshot` borrows from `db`, so `snapshot` must be dropped before `db`'s refcount
/// is decremented. This is enforced by the `Drop` impl, which manually drops the
/// snapshot before the compiler auto-drops the `Arc<DB>`.
struct SnapshotInner {
    snapshot: ManuallyDrop<rocksdb::Snapshot<'static>>,
    db: Arc<DB>,
}

impl Drop for SnapshotInner {
    fn drop(&mut self) {
        // Ensure that the snapshot is dropped before the database reference count is decremented.
        unsafe {
            ManuallyDrop::drop(&mut self.snapshot);
        }
    }
}

/// A read-only, `Clone`-able RocksDB storage that reads from a point-in-time snapshot.
///
/// All clones share the same snapshot via `Arc`, providing a consistent view of
/// the database at the time the snapshot was created.
///
/// Implements [`SmtStorageReader`] only (read-only snapshot).
#[derive(Clone)]
pub struct RocksDbSnapshotStorage {
    inner: Arc<SnapshotInner>,
}

impl std::fmt::Debug for RocksDbSnapshotStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RocksDbSnapshotStorage").finish_non_exhaustive()
    }
}

impl RocksDbSnapshotStorage {
    /// Creates a new snapshot storage from the given database.
    pub fn new(db: Arc<DB>) -> Self {
        // SAFETY: We can transmute the snapshot to a static lifetime because we know that
        // the database will outlive the snapshot.
        let snapshot = db.snapshot();
        let snapshot: rocksdb::Snapshot<'static> = unsafe { std::mem::transmute(snapshot) };
        Self {
            inner: Arc::new(SnapshotInner {
                snapshot: ManuallyDrop::new(snapshot),
                db,
            }),
        }
    }

    fn cf_handle(&self, name: &str) -> Result<&rocksdb::ColumnFamily, StorageError> {
        self.inner
            .db
            .cf_handle(name)
            .ok_or_else(|| StorageError::Unsupported(format!("unknown column family `{name}`")))
    }

    #[inline(always)]
    fn subtree_cf(&self, index: NodeIndex) -> &rocksdb::ColumnFamily {
        let name = cf_for_depth(index.depth());
        self.cf_handle(name).expect("CF handle missing")
    }
}

impl SmtStorageReader for RocksDbSnapshotStorage {
    fn leaf_count(&self) -> Result<usize, StorageError> {
        let cf = self.cf_handle(METADATA_CF)?;
        self.inner
            .snapshot
            .get_cf(cf, LEAF_COUNT_KEY)
            .map_err(map_rocksdb_err)?
            .map_or(Ok(0), |b| read_count("leaf count", &b))
    }

    fn entry_count(&self) -> Result<usize, StorageError> {
        let cf = self.cf_handle(METADATA_CF)?;
        self.inner
            .snapshot
            .get_cf(cf, ENTRY_COUNT_KEY)
            .map_err(map_rocksdb_err)?
            .map_or(Ok(0), |b| read_count("entry count", &b))
    }

    fn get_leaf(&self, index: u64) -> Result<Option<SmtLeaf>, StorageError> {
        let cf = self.cf_handle(LEAVES_CF)?;
        let key = RocksDbStorage::index_db_key(index);
        self.inner
            .snapshot
            .get_cf(cf, key)
            .map_err(map_rocksdb_err)?
            .map_or(Ok(None), read_leaf)
    }

    fn get_leaves(&self, indices: &[u64]) -> Result<Vec<Option<SmtLeaf>>, StorageError> {
        let cf = self.cf_handle(LEAVES_CF)?;
        let db_keys: Vec<[u8; 8]> =
            indices.iter().map(|&idx| RocksDbStorage::index_db_key(idx)).collect();
        let results = self.inner.snapshot.multi_get_cf(db_keys.iter().map(|k| (cf, k.as_ref())));

        let leaves = results
            .into_iter()
            .collect::<Result<Vec<Option<Vec<u8>>>, rocksdb::Error>>()
            .map_err(map_rocksdb_err)?;
        read_leaves(leaves)
    }

    fn has_leaves(&self) -> Result<bool, StorageError> {
        Ok(self.leaf_count()? > 0)
    }

    fn get_subtree(&self, index: NodeIndex) -> Result<Option<Subtree>, StorageError> {
        let cf = self.subtree_cf(index);
        let key = RocksDbStorage::subtree_db_key(index);
        read_subtree(index, self.inner.snapshot.get_cf(cf, key).map_err(map_rocksdb_err)?)
    }

    fn get_subtrees(&self, indices: &[NodeIndex]) -> Result<Vec<Option<Subtree>>, StorageError> {
        use rayon::prelude::*;

        let depth_buckets = bucket_by_depth(indices)?;
        let mut results = vec![None; indices.len()];

        let bucket_results: Result<Vec<_>, StorageError> = depth_buckets
            .into_par_iter()
            .enumerate()
            .filter(|(_, bucket)| !bucket.is_empty())
            .map(
                |(bucket_index, bucket)| -> Result<Vec<(usize, Option<Subtree>)>, StorageError> {
                    let depth = SUBTREE_DEPTHS[bucket_index];
                    let cf = self.cf_handle(cf_for_depth(depth))?;
                    let keys: Vec<_> = bucket
                        .iter()
                        .map(|(_, idx)| RocksDbStorage::subtree_db_key(*idx))
                        .collect();

                    let db_results: Vec<_> = self
                        .inner
                        .snapshot
                        .multi_get_cf(keys.iter().map(|k| (cf, k.as_ref())))
                        .into_iter()
                        .collect();

                    read_subtree_batch(bucket, db_results)
                },
            )
            .collect();

        for bucket_result in bucket_results? {
            for (original_index, subtree) in bucket_result {
                results[original_index] = subtree;
            }
        }

        Ok(results)
    }

    fn get_inner_node(&self, index: NodeIndex) -> Result<Option<InnerNode>, StorageError> {
        if index.depth() < IN_MEMORY_DEPTH {
            return Err(StorageError::Unsupported(
                "Cannot get inner node from upper part of the tree".into(),
            ));
        }
        let subtree_root_index = Subtree::find_subtree_root(index);
        Ok(self
            .get_subtree(subtree_root_index)?
            .and_then(|subtree| subtree.get_inner_node(index)))
    }

    fn iter_leaves(&self) -> Result<Box<dyn Iterator<Item = (u64, SmtLeaf)> + '_>, StorageError> {
        let cf = self.cf_handle(LEAVES_CF)?;
        let mut read_opts = ReadOptions::default();
        read_opts.set_total_order_seek(true);
        let db_iter = self.inner.snapshot.iterator_cf_opt(cf, read_opts, IteratorMode::Start);

        Ok(Box::new(RocksDbDirectLeafIterator { iter: db_iter }))
    }

    fn iter_subtrees(&self) -> Result<Box<dyn Iterator<Item = Subtree> + '_>, StorageError> {
        const SUBTREE_CFS: [&str; 5] =
            [SUBTREE_24_CF, SUBTREE_32_CF, SUBTREE_40_CF, SUBTREE_48_CF, SUBTREE_56_CF];

        let mut cf_handles = Vec::new();
        for cf_name in SUBTREE_CFS {
            cf_handles.push(self.cf_handle(cf_name)?);
        }

        Ok(Box::new(RocksDbSubtreeIterator::new(&self.inner.db, cf_handles)))
    }

    fn get_depth24(&self) -> Result<Vec<(u64, Word)>, StorageError> {
        let cf = self.cf_handle(DEPTH_24_CF)?;
        read_depth24_entries(self.inner.snapshot.iterator_cf(cf, IteratorMode::Start))
    }
}
