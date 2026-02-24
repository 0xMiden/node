//! RocksDB-backed persistent storage for Sparse Merkle Trees.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cmp::Ordering;
use std::path::PathBuf;
use std::sync::Arc;

use ::rocksdb::{
    BlockBasedOptions,
    Cache,
    ColumnFamily,
    ColumnFamilyDescriptor,
    DB,
    DBCompactionStyle,
    DBCompressionType,
    DBIteratorWithThreadMode,
    Error as RocksDbError,
    FlushOptions,
    IteratorMode,
    Options,
    ReadOptions,
    WriteBatch,
    WriteOptions,
};
use miden_crypto::Map;
use miden_crypto::merkle::smt::MAX_LEAF_ENTRIES;
use winter_utils::{Deserializable, Serializable};

use crate::{
    EMPTY_WORD,
    InnerNode,
    NodeIndex,
    SmtLeaf,
    SmtLeafError,
    SmtStorage,
    StorageError,
    StorageUpdateParts,
    StorageUpdates,
    Subtree,
    SubtreeUpdate,
    Word,
};

/// The name of the RocksDB column family used for storing SMT leaves.
const LEAVES_CF: &str = "leaves";
/// The names of the RocksDB column families used for storing SMT subtrees (deep nodes).
const SUBTREE_24_CF: &str = "st24";
const SUBTREE_32_CF: &str = "st32";
const SUBTREE_40_CF: &str = "st40";
const SUBTREE_48_CF: &str = "st48";
const SUBTREE_56_CF: &str = "st56";

/// The name of the RocksDB column family used for storing metadata (e.g., root, counts).
const METADATA_CF: &str = "metadata";
/// The name of the RocksDB column family used for storing level 24 hashes for fast tree rebuilding.
const DEPTH_24_CF: &str = "depth24";

/// The key used in the `METADATA_CF` column family to store the SMT's root hash.
const ROOT_KEY: &[u8] = b"smt_root";
/// The key used in the `METADATA_CF` column family to store the total count of non-empty leaves.
const LEAF_COUNT_KEY: &[u8] = b"leaf_count";
/// The key used in the `METADATA_CF` column family to store the total count of key-value entries.
const ENTRY_COUNT_KEY: &[u8] = b"entry_count";

trait RocksDbResultExt<T> {
    fn map_rocksdb_err(self) -> Result<T, StorageError>;
}

impl<T> RocksDbResultExt<T> for Result<T, RocksDbError> {
    fn map_rocksdb_err(self) -> Result<T, StorageError> {
        self.map_err(rocksdb_error_to_storage_error)
    }
}

/// A RocksDB-backed persistent storage implementation for a Sparse Merkle Tree (SMT).
///
/// Implements the `SmtStorage` trait, providing durable storage for SMT components
/// including leaves, subtrees (for deeper parts of the tree), and metadata like the SMT root
/// and counts. It leverages RocksDB column families to organize data:
/// - `LEAVES_CF` ("leaves"): Stores `SmtLeaf` data, keyed by their logical u64 index.
/// - `SUBTREE_24_CF` ("st24"): Stores serialized `Subtree` data at depth 24.
/// - `SUBTREE_32_CF` ("st32"): Stores serialized `Subtree` data at depth 32.
/// - `SUBTREE_40_CF` ("st40"): Stores serialized `Subtree` data at depth 40.
/// - `SUBTREE_48_CF` ("st48"): Stores serialized `Subtree` data at depth 48.
/// - `SUBTREE_56_CF` ("st56"): Stores serialized `Subtree` data at depth 56.
/// - `METADATA_CF` ("metadata"): Stores overall SMT metadata such as the current root hash, total
///   leaf count, and total entry count.
#[derive(Debug, Clone)]
pub struct RocksDbStorage {
    db: Arc<DB>,
}

impl RocksDbStorage {
    /// Opens or creates a RocksDB database at the specified `path` and configures it for SMT
    /// storage.
    ///
    /// This method sets up the necessary column families (`leaves`, `subtrees`, `metadata`)
    /// and applies various RocksDB options for performance, such as caching, bloom filters,
    /// and compaction strategies tailored for SMT workloads.
    ///
    /// # Errors
    /// Returns `StorageError::Backend` if the database cannot be opened or configured,
    /// for example, due to path issues, permissions, or RocksDB internal errors.
    pub fn open(config: RocksDbConfig) -> Result<Self, StorageError> {
        // Base DB options
        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);
        db_opts.increase_parallelism(rayon::current_num_threads() as i32);
        db_opts.set_max_open_files(config.max_open_files);
        db_opts.set_max_background_jobs(rayon::current_num_threads() as i32);
        db_opts.set_max_total_wal_size(512 * 1024 * 1024);

        // Shared block cache across all column families
        let cache = Cache::new_lru_cache(config.cache_size);

        // Common table options for bloom filtering and cache
        let mut table_opts = BlockBasedOptions::default();
        table_opts.set_block_cache(&cache);
        table_opts.set_bloom_filter(10.0, false);
        table_opts.set_whole_key_filtering(true);
        table_opts.set_pin_l0_filter_and_index_blocks_in_cache(true);

        // Column family for leaves
        let mut leaves_opts = Options::default();
        leaves_opts.set_block_based_table_factory(&table_opts);
        leaves_opts.set_write_buffer_size(128 << 20);
        leaves_opts.set_max_write_buffer_number(3);
        leaves_opts.set_min_write_buffer_number_to_merge(1);
        leaves_opts.set_max_write_buffer_size_to_maintain(0);
        leaves_opts.set_compaction_style(DBCompactionStyle::Level);
        leaves_opts.set_target_file_size_base(512 << 20);
        leaves_opts.set_target_file_size_multiplier(2);
        leaves_opts.set_compression_type(DBCompressionType::Lz4);
        leaves_opts.set_level_zero_file_num_compaction_trigger(8);

        // Helper to build subtree CF options
        fn subtree_cf(cache: &Cache, bloom_filter_bits: f64) -> Options {
            let mut tbl = BlockBasedOptions::default();
            tbl.set_block_cache(cache);
            tbl.set_bloom_filter(bloom_filter_bits, false);
            tbl.set_whole_key_filtering(true);
            tbl.set_pin_l0_filter_and_index_blocks_in_cache(true);

            let mut opts = Options::default();
            opts.set_block_based_table_factory(&tbl);
            opts.set_write_buffer_size(128 << 20);
            opts.set_max_write_buffer_number(3);
            opts.set_min_write_buffer_number_to_merge(1);
            opts.set_max_write_buffer_size_to_maintain(0);
            opts.set_compaction_style(DBCompactionStyle::Level);
            opts.set_level_zero_file_num_compaction_trigger(4);
            opts.set_target_file_size_base(512 << 20);
            opts.set_target_file_size_multiplier(2);
            opts.set_compression_type(DBCompressionType::Lz4);
            opts.set_level_zero_file_num_compaction_trigger(8);
            opts
        }

        let mut depth24_opts = Options::default();
        depth24_opts.set_compression_type(DBCompressionType::Lz4);
        depth24_opts.set_block_based_table_factory(&table_opts);

        let mut metadata_opts = Options::default();
        metadata_opts.set_compression_type(DBCompressionType::None);

        let cfs = vec![
            ColumnFamilyDescriptor::new(LEAVES_CF, leaves_opts),
            ColumnFamilyDescriptor::new(SUBTREE_24_CF, subtree_cf(&cache, 8.0)),
            ColumnFamilyDescriptor::new(SUBTREE_32_CF, subtree_cf(&cache, 10.0)),
            ColumnFamilyDescriptor::new(SUBTREE_40_CF, subtree_cf(&cache, 10.0)),
            ColumnFamilyDescriptor::new(SUBTREE_48_CF, subtree_cf(&cache, 12.0)),
            ColumnFamilyDescriptor::new(SUBTREE_56_CF, subtree_cf(&cache, 12.0)),
            ColumnFamilyDescriptor::new(METADATA_CF, metadata_opts),
            ColumnFamilyDescriptor::new(DEPTH_24_CF, depth24_opts),
        ];

        let db = DB::open_cf_descriptors(&db_opts, config.path, cfs).map_rocksdb_err()?;

        Ok(Self { db: Arc::new(db) })
    }

    /// Syncs the RocksDB database to disk.
    fn sync(&self) -> Result<(), StorageError> {
        let mut fopts = FlushOptions::default();
        fopts.set_wait(true);

        for name in [
            LEAVES_CF,
            SUBTREE_24_CF,
            SUBTREE_32_CF,
            SUBTREE_40_CF,
            SUBTREE_48_CF,
            SUBTREE_56_CF,
            METADATA_CF,
            DEPTH_24_CF,
        ] {
            let cf = self.cf_handle(name)?;
            self.db.flush_cf_opt(cf, &fopts).map_rocksdb_err()?;
        }

        self.db.flush_wal(true).map_rocksdb_err()?;
        Ok(())
    }

    #[inline(always)]
    fn index_db_key(index: u64) -> [u8; 8] {
        index.to_be_bytes()
    }

    #[inline(always)]
    fn subtree_db_key(index: NodeIndex) -> KeyBytes {
        let keep = match index.depth() {
            24 => 3,
            32 => 4,
            40 => 5,
            48 => 6,
            56 => 7,
            d => panic!("unsupported depth {d}"),
        };
        KeyBytes::new(index.value(), keep)
    }

    fn cf_handle(&self, name: &str) -> Result<&ColumnFamily, StorageError> {
        self.db
            .cf_handle(name)
            .ok_or_else(|| StorageError::Unsupported(format!("unknown column family `{name}`")))
    }

    #[inline(always)]
    fn subtree_cf(&self, index: NodeIndex) -> &ColumnFamily {
        let name = cf_for_depth(index.depth());
        self.cf_handle(name).expect("CF handle missing")
    }
}

impl SmtStorage for RocksDbStorage {
    fn get_root(&self) -> Result<Option<Word>, StorageError> {
        let cf = self.cf_handle(METADATA_CF)?;
        match self.db.get_cf(cf, ROOT_KEY).map_rocksdb_err()? {
            Some(bytes) => {
                let digest = Word::read_from_bytes(&bytes)?;
                Ok(Some(digest))
            },
            None => Ok(None),
        }
    }

    fn set_root(&self, root: Word) -> Result<(), StorageError> {
        let cf = self.cf_handle(METADATA_CF)?;
        self.db.put_cf(cf, ROOT_KEY, root.to_bytes()).map_rocksdb_err()?;
        Ok(())
    }

    fn leaf_count(&self) -> Result<usize, StorageError> {
        let cf = self.cf_handle(METADATA_CF)?;
        self.db.get_cf(cf, LEAF_COUNT_KEY).map_rocksdb_err()?.map_or(Ok(0), |bytes| {
            let arr: [u8; 8] =
                bytes.as_slice().try_into().map_err(|_| StorageError::BadValueLen {
                    what: "leaf count",
                    expected: 8,
                    found: bytes.len(),
                })?;
            Ok(usize::from_be_bytes(arr))
        })
    }

    fn entry_count(&self) -> Result<usize, StorageError> {
        let cf = self.cf_handle(METADATA_CF)?;
        self.db.get_cf(cf, ENTRY_COUNT_KEY).map_rocksdb_err()?.map_or(Ok(0), |bytes| {
            let arr: [u8; 8] =
                bytes.as_slice().try_into().map_err(|_| StorageError::BadValueLen {
                    what: "entry count",
                    expected: 8,
                    found: bytes.len(),
                })?;
            Ok(usize::from_be_bytes(arr))
        })
    }

    fn insert_value(
        &self,
        index: u64,
        key: Word,
        value: Word,
    ) -> Result<Option<Word>, StorageError> {
        debug_assert_ne!(value, EMPTY_WORD);

        let mut batch = WriteBatch::default();

        let mut current_leaf_count = self.leaf_count()?;
        let mut current_entry_count = self.entry_count()?;

        let leaves_cf = self.cf_handle(LEAVES_CF)?;
        let db_key = Self::index_db_key(index);

        let maybe_leaf = self.get_leaf(index)?;

        let (old_value, new_leaf) = match maybe_leaf {
            Some(existing_leaf) => {
                let (old_val, updated_leaf) = insert_leaf_entry(existing_leaf, key, value)?;
                if old_val.is_none() {
                    current_entry_count += 1;
                }
                (old_val, updated_leaf)
            },
            None => {
                let new_leaf = SmtLeaf::new_single(key, value);
                current_leaf_count += 1;
                current_entry_count += 1;
                (None, new_leaf)
            },
        };

        batch.put_cf(leaves_cf, db_key, new_leaf.to_bytes());

        let metadata_cf = self.cf_handle(METADATA_CF)?;
        batch.put_cf(metadata_cf, LEAF_COUNT_KEY, current_leaf_count.to_be_bytes());
        batch.put_cf(metadata_cf, ENTRY_COUNT_KEY, current_entry_count.to_be_bytes());

        self.db.write(batch).map_rocksdb_err()?;

        Ok(old_value)
    }

    fn remove_value(&self, index: u64, key: Word) -> Result<Option<Word>, StorageError> {
        let maybe_leaf = self.get_leaf(index)?;

        let Some(existing_leaf) = maybe_leaf else {
            return Ok(None);
        };

        let (old_value, is_empty, updated_leaf) = remove_leaf_entry(existing_leaf, key);
        if old_value.is_none() {
            return Ok(None);
        }

        let mut batch = WriteBatch::default();
        let leaves_cf = self.cf_handle(LEAVES_CF)?;
        let db_key = Self::index_db_key(index);

        let mut current_leaf_count = self.leaf_count()?;
        let mut current_entry_count = self.entry_count()?;

        if is_empty {
            batch.delete_cf(leaves_cf, db_key);
            current_leaf_count = current_leaf_count.saturating_sub(1);
        } else {
            batch.put_cf(leaves_cf, db_key, updated_leaf.to_bytes());
        }
        current_entry_count = current_entry_count.saturating_sub(1);

        let metadata_cf = self.cf_handle(METADATA_CF)?;
        batch.put_cf(metadata_cf, LEAF_COUNT_KEY, current_leaf_count.to_be_bytes());
        batch.put_cf(metadata_cf, ENTRY_COUNT_KEY, current_entry_count.to_be_bytes());

        self.db.write(batch).map_rocksdb_err()?;

        Ok(old_value)
    }

    fn get_leaf(&self, index: u64) -> Result<Option<SmtLeaf>, StorageError> {
        let cf = self.cf_handle(LEAVES_CF)?;
        let db_key = Self::index_db_key(index);

        match self.db.get_cf(cf, db_key).map_rocksdb_err()? {
            Some(bytes) => Ok(Some(SmtLeaf::read_from_bytes(&bytes)?)),
            None => Ok(None),
        }
    }

    fn set_leaves(&self, leaves: Map<u64, SmtLeaf>) -> Result<(), StorageError> {
        let leaves_cf = self.cf_handle(LEAVES_CF)?;
        let mut batch = WriteBatch::default();

        for (index, leaf) in leaves {
            let db_key = Self::index_db_key(index);
            batch.put_cf(leaves_cf, db_key, leaf.to_bytes());
        }

        self.db.write(batch).map_rocksdb_err()?;
        Ok(())
    }

    fn remove_leaf(&self, index: u64) -> Result<Option<SmtLeaf>, StorageError> {
        let cf = self.cf_handle(LEAVES_CF)?;
        let db_key = Self::index_db_key(index);

        let old_leaf = match self.db.get_cf(cf, &db_key).map_rocksdb_err()? {
            Some(bytes) => Some(SmtLeaf::read_from_bytes(&bytes)?),
            None => None,
        };

        if old_leaf.is_some() {
            self.db.delete_cf(cf, db_key).map_rocksdb_err()?;
        }

        Ok(old_leaf)
    }

    fn get_leaves(&self, indices: &[u64]) -> Result<Vec<Option<SmtLeaf>>, StorageError> {
        let cf = self.cf_handle(LEAVES_CF)?;
        let keys: Vec<[u8; 8]> = indices.iter().map(|idx| Self::index_db_key(*idx)).collect();
        let key_refs: Vec<(&ColumnFamily, &[u8])> =
            keys.iter().map(|k| (cf, k.as_slice())).collect();

        let results = self.db.multi_get_cf(key_refs);
        let mut out = Vec::with_capacity(indices.len());
        for res in results {
            match res.map_rocksdb_err()? {
                Some(bytes) => out.push(Some(SmtLeaf::read_from_bytes(&bytes)?)),
                None => out.push(None),
            }
        }
        Ok(out)
    }

    fn has_leaves(&self) -> Result<bool, StorageError> {
        Ok(self.leaf_count()? > 0)
    }

    fn get_subtree(&self, index: NodeIndex) -> Result<Option<Subtree>, StorageError> {
        let cf = self.subtree_cf(index);
        let key = Self::subtree_db_key(index);

        match self.db.get_cf(cf, key).map_rocksdb_err()? {
            Some(bytes) => Ok(Some(Subtree::from_vec(index, &bytes)?)),
            None => Ok(None),
        }
    }

    fn get_subtrees(&self, indices: &[NodeIndex]) -> Result<Vec<Option<Subtree>>, StorageError> {
        let keys: Vec<(NodeIndex, KeyBytes)> =
            indices.iter().map(|&idx| (idx, Self::subtree_db_key(idx))).collect();

        let key_refs: Vec<(&ColumnFamily, &[u8])> =
            keys.iter().map(|(idx, k)| (self.subtree_cf(*idx), k.as_slice())).collect();

        let results = self.db.multi_get_cf(key_refs);
        let mut out = Vec::with_capacity(indices.len());

        for (res, &idx) in results.into_iter().zip(indices.iter()) {
            match res.map_rocksdb_err()? {
                Some(bytes) => out.push(Some(Subtree::from_vec(idx, &bytes)?)),
                None => out.push(None),
            }
        }
        Ok(out)
    }

    fn set_subtree(&self, subtree: &Subtree) -> Result<(), StorageError> {
        let index = subtree.root_index();
        let cf = self.subtree_cf(index);
        let key = Self::subtree_db_key(index);
        let data = subtree.to_vec();

        self.db.put_cf(cf, key, data).map_rocksdb_err()?;
        Ok(())
    }

    fn set_subtrees(&self, subtrees: Vec<Subtree>) -> Result<(), StorageError> {
        let mut batch = WriteBatch::default();

        for subtree in subtrees {
            let index = subtree.root_index();
            let cf = self.subtree_cf(index);
            let key = Self::subtree_db_key(index);
            let data = subtree.to_vec();
            batch.put_cf(cf, key, data);
        }

        self.db.write(batch).map_rocksdb_err()?;
        Ok(())
    }

    fn remove_subtree(&self, index: NodeIndex) -> Result<(), StorageError> {
        let cf = self.subtree_cf(index);
        let key = Self::subtree_db_key(index);
        self.db.delete_cf(cf, key).map_rocksdb_err()?;
        Ok(())
    }

    fn get_inner_node(&self, index: NodeIndex) -> Result<Option<InnerNode>, StorageError> {
        let subtree = self.get_subtree(index)?;
        Ok(subtree.and_then(|s| s.get_inner_node(index)))
    }

    fn set_inner_node(
        &self,
        index: NodeIndex,
        node: InnerNode,
    ) -> Result<Option<InnerNode>, StorageError> {
        let mut subtree = self.get_subtree(index)?.unwrap_or_else(|| Subtree::new(index));
        let old = subtree.insert_inner_node(index, node);
        self.set_subtree(&subtree)?;
        Ok(old)
    }

    fn remove_inner_node(&self, index: NodeIndex) -> Result<Option<InnerNode>, StorageError> {
        let Some(mut subtree) = self.get_subtree(index)? else {
            return Ok(None);
        };
        let old = subtree.remove_inner_node(index);
        if subtree.is_empty() {
            self.remove_subtree(index)?;
        } else {
            self.set_subtree(&subtree)?;
        }
        Ok(old)
    }

    fn apply(&self, updates: StorageUpdates) -> Result<(), StorageError> {
        let StorageUpdateParts {
            new_root,
            leaf_updates,
            subtree_updates,
            leaf_count_delta,
            entry_count_delta,
        } = updates.into_parts();

        let mut batch = WriteBatch::default();

        let leaves_cf = self.cf_handle(LEAVES_CF)?;
        let metadata_cf = self.cf_handle(METADATA_CF)?;
        let depth24_cf = self.cf_handle(DEPTH_24_CF)?;

        // Process leaf updates
        for (index, maybe_leaf) in leaf_updates {
            let key = Self::index_db_key(index);
            match maybe_leaf {
                Some(leaf) => batch.put_cf(leaves_cf, key, leaf.to_bytes()),
                None => batch.delete_cf(leaves_cf, key),
            }
        }

        // Process subtree updates
        let subtree_ops: Result<Vec<_>, StorageError> = subtree_updates
            .into_iter()
            .map(|update| {
                let (index, maybe_bytes, depth24_op) = match update {
                    SubtreeUpdate::Store { index, subtree } => {
                        let bytes = subtree.to_vec();
                        let depth24_op = if index.depth() == 24 {
                            let hash_key = Self::index_db_key(index.value());
                            let root_hash = subtree
                                .get_inner_node(index)
                                .ok_or_else(|| {
                                    StorageError::Unsupported(
                                        "Subtree root node not found".to_string(),
                                    )
                                })?
                                .hash();
                            Some((hash_key, Some(root_hash.to_bytes())))
                        } else {
                            None
                        };
                        (index, Some(bytes), depth24_op)
                    },
                    SubtreeUpdate::Delete { index } => {
                        let depth24_op = if index.depth() == 24 {
                            let hash_key = Self::index_db_key(index.value());
                            Some((hash_key, None))
                        } else {
                            None
                        };
                        (index, None, depth24_op)
                    },
                };

                let key = Self::subtree_db_key(index);
                let subtrees_cf = self.subtree_cf(index);

                Ok((subtrees_cf, key, maybe_bytes, depth24_op))
            })
            .collect();

        for (subtrees_cf, key, maybe_bytes, depth24_op) in subtree_ops? {
            match maybe_bytes {
                Some(bytes) => batch.put_cf(subtrees_cf, key, bytes),
                None => batch.delete_cf(subtrees_cf, key),
            }

            if let Some((hash_key, maybe_hash_bytes)) = depth24_op {
                match maybe_hash_bytes {
                    Some(hash_bytes) => batch.put_cf(depth24_cf, hash_key, hash_bytes),
                    None => batch.delete_cf(depth24_cf, hash_key),
                }
            }
        }

        if leaf_count_delta != 0 || entry_count_delta != 0 {
            let current_leaf_count = self.leaf_count()?;
            let current_entry_count = self.entry_count()?;

            let new_leaf_count = current_leaf_count.saturating_add_signed(leaf_count_delta);
            let new_entry_count = current_entry_count.saturating_add_signed(entry_count_delta);

            batch.put_cf(metadata_cf, LEAF_COUNT_KEY, new_leaf_count.to_be_bytes());
            batch.put_cf(metadata_cf, ENTRY_COUNT_KEY, new_entry_count.to_be_bytes());
        }

        batch.put_cf(metadata_cf, ROOT_KEY, new_root.to_bytes());

        let mut write_opts = WriteOptions::default();
        write_opts.set_sync(false);
        self.db.write_opt(batch, &write_opts).map_rocksdb_err()?;

        Ok(())
    }

    fn iter_leaves(&self) -> Result<Box<dyn Iterator<Item = (u64, SmtLeaf)> + '_>, StorageError> {
        let cf = self.cf_handle(LEAVES_CF)?;
        let mut read_opts = ReadOptions::default();
        read_opts.set_total_order_seek(true);
        let db_iter = self.db.iterator_cf_opt(cf, read_opts, IteratorMode::Start);

        Ok(Box::new(RocksDbDirectLeafIterator { iter: db_iter }))
    }

    fn iter_subtrees(&self) -> Result<Box<dyn Iterator<Item = Subtree> + '_>, StorageError> {
        const SUBTREE_CFS: [&str; 5] =
            [SUBTREE_24_CF, SUBTREE_32_CF, SUBTREE_40_CF, SUBTREE_48_CF, SUBTREE_56_CF];

        let mut cf_handles = Vec::new();
        for cf_name in SUBTREE_CFS {
            cf_handles.push(self.cf_handle(cf_name)?);
        }

        Ok(Box::new(RocksDbSubtreeIterator::new(&self.db, cf_handles)))
    }

    fn get_depth24(&self) -> Result<Vec<(u64, Word)>, StorageError> {
        let cf = self.cf_handle(DEPTH_24_CF)?;
        let iter = self.db.iterator_cf(cf, IteratorMode::Start);
        let mut hashes = Vec::new();

        for item in iter {
            let (key_bytes, value_bytes) = item.map_rocksdb_err()?;

            let index = index_from_key_bytes(&key_bytes)?;
            let hash = Word::read_from_bytes(&value_bytes)?;

            hashes.push((index, hash));
        }

        Ok(hashes)
    }
}

impl Drop for RocksDbStorage {
    fn drop(&mut self) {
        if let Err(e) = self.sync() {
            panic!("failed to flush RocksDB on drop: {e}");
        }
    }
}

// ITERATORS
// --------------------------------------------------------------------------------------------

struct RocksDbDirectLeafIterator<'a> {
    iter: DBIteratorWithThreadMode<'a, DB>,
}

impl Iterator for RocksDbDirectLeafIterator<'_> {
    type Item = (u64, SmtLeaf);

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.find_map(|result| {
            let (key_bytes, value_bytes) = result.ok()?;
            let leaf_idx = index_from_key_bytes(&key_bytes).ok()?;
            let leaf = SmtLeaf::read_from_bytes(&value_bytes).ok()?;
            Some((leaf_idx, leaf))
        })
    }
}

struct RocksDbSubtreeIterator<'a> {
    db: &'a DB,
    cf_handles: Vec<&'a ColumnFamily>,
    current_cf_index: usize,
    current_iter: Option<DBIteratorWithThreadMode<'a, DB>>,
}

impl<'a> RocksDbSubtreeIterator<'a> {
    fn new(db: &'a DB, cf_handles: Vec<&'a ColumnFamily>) -> Self {
        let mut iterator = Self {
            db,
            cf_handles,
            current_cf_index: 0,
            current_iter: None,
        };
        iterator.advance_to_next_cf();
        iterator
    }

    fn advance_to_next_cf(&mut self) {
        if self.current_cf_index < self.cf_handles.len() {
            let cf = self.cf_handles[self.current_cf_index];
            let mut read_opts = ReadOptions::default();
            read_opts.set_total_order_seek(true);
            self.current_iter = Some(self.db.iterator_cf_opt(cf, read_opts, IteratorMode::Start));
        } else {
            self.current_iter = None;
        }
    }

    fn try_next_from_iter(
        iter: &mut DBIteratorWithThreadMode<DB>,
        cf_index: usize,
    ) -> Option<Subtree> {
        iter.find_map(|result| {
            let (key_bytes, value_bytes) = result.ok()?;
            let depth = 24 + (cf_index * 8) as u8;

            let node_idx = subtree_root_from_key_bytes(&key_bytes, depth).ok()?;
            Subtree::from_vec(node_idx, &value_bytes).ok()
        })
    }
}

impl Iterator for RocksDbSubtreeIterator<'_> {
    type Item = Subtree;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let iter = self.current_iter.as_mut()?;

            if let Some(subtree) = Self::try_next_from_iter(iter, self.current_cf_index) {
                return Some(subtree);
            }

            self.current_cf_index += 1;
            self.advance_to_next_cf();

            self.current_iter.as_ref()?;
        }
    }
}

// ROCKSDB CONFIGURATION
// --------------------------------------------------------------------------------------------

/// Configuration for RocksDB storage used by the Sparse Merkle Tree implementation.
#[derive(Debug, Clone)]
pub struct RocksDbConfig {
    pub(crate) path: PathBuf,
    pub(crate) cache_size: usize,
    pub(crate) max_open_files: i32,
}

impl RocksDbConfig {
    /// Creates a new RocksDbConfig with the given database path and default settings.
    pub fn new<P: Into<PathBuf>>(path: P) -> Self {
        Self {
            path: path.into(),
            cache_size: 1 << 30,
            max_open_files: 512,
        }
    }

    /// Sets the block cache size for RocksDB.
    pub fn with_cache_size(mut self, size: usize) -> Self {
        self.cache_size = size;
        self
    }

    /// Sets the maximum number of files that RocksDB can have open simultaneously.
    pub fn with_max_open_files(mut self, count: i32) -> Self {
        self.max_open_files = count;
        self
    }
}

// SUBTREE DB KEY
// --------------------------------------------------------------------------------------------

#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash)]
pub(crate) struct KeyBytes {
    bytes: [u8; 8],
    len: u8,
}

impl KeyBytes {
    #[inline(always)]
    pub fn new(value: u64, keep: usize) -> Self {
        debug_assert!((3..=7).contains(&keep));
        let bytes = value.to_be_bytes();
        debug_assert!(bytes[..8 - keep].iter().all(|&b| b == 0));
        Self { bytes, len: keep as u8 }
    }

    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[8 - self.len as usize..]
    }
}

impl AsRef<[u8]> for KeyBytes {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

// HELPERS
// --------------------------------------------------------------------------------------------

fn index_from_key_bytes(key_bytes: &[u8]) -> Result<u64, StorageError> {
    if key_bytes.len() != 8 {
        return Err(StorageError::BadKeyLen { expected: 8, found: key_bytes.len() });
    }
    let mut arr = [0u8; 8];
    arr.copy_from_slice(key_bytes);
    Ok(u64::from_be_bytes(arr))
}

#[inline(always)]
fn subtree_root_from_key_bytes(key_bytes: &[u8], depth: u8) -> Result<NodeIndex, StorageError> {
    let expected = match depth {
        24 => 3,
        32 => 4,
        40 => 5,
        48 => 6,
        56 => 7,
        d => return Err(StorageError::Unsupported(format!("unsupported subtree depth {d}"))),
    };

    if key_bytes.len() != expected {
        return Err(StorageError::BadSubtreeKeyLen { depth, expected, found: key_bytes.len() });
    }
    let mut buf = [0u8; 8];
    buf[8 - expected..].copy_from_slice(key_bytes);
    let value = u64::from_be_bytes(buf);
    Ok(NodeIndex::new_unchecked(depth, value))
}

#[inline(always)]
fn cf_for_depth(depth: u8) -> &'static str {
    match depth {
        24 => SUBTREE_24_CF,
        32 => SUBTREE_32_CF,
        40 => SUBTREE_40_CF,
        48 => SUBTREE_48_CF,
        56 => SUBTREE_56_CF,
        _ => panic!("unsupported subtree depth: {depth}"),
    }
}

fn insert_leaf_entry(
    leaf: SmtLeaf,
    key: Word,
    value: Word,
) -> Result<(Option<Word>, SmtLeaf), StorageError> {
    match leaf {
        SmtLeaf::Empty(_) => Ok((None, SmtLeaf::new_single(key, value))),
        SmtLeaf::Single((key_at_leaf, value_at_leaf)) => {
            if key_at_leaf == key {
                Ok((Some(value_at_leaf), SmtLeaf::Single((key_at_leaf, value))))
            } else {
                let mut pairs = vec![(key_at_leaf, value_at_leaf), (key, value)];
                pairs.sort_by(|(key_1, _), (key_2, _)| cmp_keys(*key_1, *key_2));
                Ok((None, SmtLeaf::Multiple(pairs)))
            }
        },
        SmtLeaf::Multiple(mut kv_pairs) => {
            match kv_pairs.binary_search_by(|kv_pair| cmp_keys(kv_pair.0, key)) {
                Ok(pos) => {
                    let old_value = kv_pairs[pos].1;
                    kv_pairs[pos].1 = value;
                    Ok((Some(old_value), SmtLeaf::Multiple(kv_pairs)))
                },
                Err(pos) => {
                    if kv_pairs.len() >= MAX_LEAF_ENTRIES {
                        return Err(SmtLeafError::TooManyLeafEntries {
                            actual: kv_pairs.len() + 1,
                        }
                        .into());
                    }
                    kv_pairs.insert(pos, (key, value));
                    Ok((None, SmtLeaf::Multiple(kv_pairs)))
                },
            }
        },
    }
}

fn remove_leaf_entry(leaf: SmtLeaf, key: Word) -> (Option<Word>, bool, SmtLeaf) {
    match leaf {
        SmtLeaf::Empty(_) => (None, false, leaf),
        SmtLeaf::Single((key_at_leaf, value_at_leaf)) => {
            if key_at_leaf == key {
                (Some(value_at_leaf), true, SmtLeaf::new_empty(key.into()))
            } else {
                (None, false, SmtLeaf::Single((key_at_leaf, value_at_leaf)))
            }
        },
        SmtLeaf::Multiple(mut kv_pairs) => {
            match kv_pairs.binary_search_by(|kv_pair| cmp_keys(kv_pair.0, key)) {
                Ok(pos) => {
                    let old_value = kv_pairs[pos].1;
                    kv_pairs.remove(pos);
                    if kv_pairs.len() == 1 {
                        (Some(old_value), false, SmtLeaf::Single(kv_pairs[0]))
                    } else {
                        (Some(old_value), false, SmtLeaf::Multiple(kv_pairs))
                    }
                },
                Err(_) => (None, false, SmtLeaf::Multiple(kv_pairs)),
            }
        },
    }
}

fn cmp_keys(key_1: Word, key_2: Word) -> Ordering {
    for (v1, v2) in key_1.iter().zip(key_2.iter()).rev() {
        let v1 = v1.as_int();
        let v2 = v2.as_int();
        if v1 != v2 {
            return v1.cmp(&v2);
        }
    }

    Ordering::Equal
}

fn rocksdb_error_to_storage_error(err: RocksDbError) -> StorageError {
    StorageError::Backend(Box::new(err))
}
