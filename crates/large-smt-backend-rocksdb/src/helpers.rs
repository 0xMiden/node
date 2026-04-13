use alloc::boxed::Box;
use alloc::vec::Vec;

use miden_crypto::merkle::NodeIndex;
use miden_crypto::merkle::smt::{MAX_LEAF_ENTRIES, SmtLeaf, SmtLeafError, Subtree};
use miden_crypto::utils::Deserializable;
use miden_crypto::word::LexicographicWord;
use rocksdb::Error as RocksDbError;

use crate::{StorageError, Word};

pub(crate) fn map_rocksdb_err(err: RocksDbError) -> StorageError {
    StorageError::Backend(Box::new(err))
}

pub(crate) fn insert_into_leaf(
    leaf: &mut SmtLeaf,
    key: Word,
    value: Word,
) -> Result<Option<Word>, StorageError> {
    match leaf {
        SmtLeaf::Empty(_) => {
            *leaf = SmtLeaf::new_single(key, value);
            Ok(None)
        },
        SmtLeaf::Single(kv_pair) => {
            if kv_pair.0 == key {
                let old_value = kv_pair.1;
                kv_pair.1 = value;
                Ok(Some(old_value))
            } else {
                let mut pairs = vec![*kv_pair, (key, value)];
                pairs.sort_by(|(key_1, _), (key_2, _)| {
                    LexicographicWord::from(*key_1).cmp(&LexicographicWord::from(*key_2))
                });
                *leaf = SmtLeaf::Multiple(pairs);
                Ok(None)
            }
        },
        SmtLeaf::Multiple(kv_pairs) => match kv_pairs.binary_search_by(|kv_pair| {
            LexicographicWord::from(kv_pair.0).cmp(&LexicographicWord::from(key))
        }) {
            Ok(pos) => {
                let old_value = kv_pairs[pos].1;
                kv_pairs[pos].1 = value;
                Ok(Some(old_value))
            },
            Err(pos) => {
                if kv_pairs.len() >= MAX_LEAF_ENTRIES {
                    return Err(StorageError::Leaf(SmtLeafError::TooManyLeafEntries {
                        actual: kv_pairs.len() + 1,
                    }));
                }
                kv_pairs.insert(pos, (key, value));
                Ok(None)
            },
        },
    }
}

pub(crate) fn remove_from_leaf(leaf: &mut SmtLeaf, key: Word) -> (Option<Word>, bool) {
    match leaf {
        SmtLeaf::Empty(_) => (None, false),
        SmtLeaf::Single((key_at_leaf, value_at_leaf)) => {
            if *key_at_leaf == key {
                let old_value = *value_at_leaf;
                *leaf = SmtLeaf::new_empty(key.into());
                (Some(old_value), true)
            } else {
                (None, false)
            }
        },
        SmtLeaf::Multiple(kv_pairs) => match kv_pairs.binary_search_by(|kv_pair| {
            LexicographicWord::from(kv_pair.0).cmp(&LexicographicWord::from(key))
        }) {
            Ok(pos) => {
                let old_value = kv_pairs[pos].1;
                kv_pairs.remove(pos);
                debug_assert!(!kv_pairs.is_empty());
                if kv_pairs.len() == 1 {
                    *leaf = SmtLeaf::Single(kv_pairs[0]);
                }
                (Some(old_value), false)
            },
            Err(_) => (None, false),
        },
    }
}

pub(crate) fn read_count(what: &'static str, bytes: &[u8]) -> Result<usize, StorageError> {
    let arr: [u8; 8] = bytes.try_into().map_err(|_| StorageError::BadValueLen {
        what,
        expected: 8,
        found: bytes.len(),
    })?;
    Ok(usize::from_be_bytes(arr))
}

#[expect(clippy::needless_pass_by_value, reason = "simplifies chaining")]
pub(crate) fn read_leaf(leaf_bytes: Vec<u8>) -> Result<Option<SmtLeaf>, StorageError> {
    let leaf = SmtLeaf::read_from_bytes(&leaf_bytes)?;
    Ok(Some(leaf))
}

pub(crate) fn read_leaves(
    leaves: Vec<Option<Vec<u8>>>,
) -> Result<Vec<Option<SmtLeaf>>, StorageError> {
    leaves
        .into_iter()
        .map(|leaf| match leaf {
            Some(bytes) => Ok(Some(SmtLeaf::read_from_bytes(&bytes)?)),
            None => Ok(None),
        })
        .collect()
}

pub(crate) fn read_subtree(
    index: NodeIndex,
    db_result: Option<Vec<u8>>,
) -> Result<Option<Subtree>, StorageError> {
    match db_result {
        Some(bytes) => {
            let subtree = Subtree::from_vec(index, &bytes)?;
            Ok(Some(subtree))
        },
        None => Ok(None),
    }
}

/// Deserializes a batch of raw `multi_get` results into subtrees, preserving the original
/// indices for reassembly.
pub(crate) fn read_subtree_batch(
    bucket: Vec<(usize, NodeIndex)>,
    db_results: Vec<Result<Option<Vec<u8>>, RocksDbError>>,
) -> Result<Vec<(usize, Option<Subtree>)>, StorageError> {
    bucket
        .into_iter()
        .zip(db_results)
        .map(|((original_index, node_index), db_result)| {
            let subtree = match db_result {
                Ok(Some(bytes)) => Some(Subtree::from_vec(node_index, &bytes)?),
                Ok(None) => None,
                Err(e) => return Err(map_rocksdb_err(e)),
            };
            Ok((original_index, subtree))
        })
        .collect()
}

/// Buckets subtree node indices by depth for batched column family lookups.
///
/// Returns an array of 5 buckets (for depths 56, 48, 40, 32, 24), where each bucket
/// contains `(original_index, NodeIndex)` pairs.
pub(crate) fn bucket_by_depth(
    indices: &[NodeIndex],
) -> Result<[Vec<(usize, NodeIndex)>; 5], StorageError> {
    let mut depth_buckets: [Vec<(usize, NodeIndex)>; 5] = Default::default();

    for (original_index, &node_index) in indices.iter().enumerate() {
        let depth = node_index.depth();
        let bucket_index = match depth {
            56 => 0,
            48 => 1,
            40 => 2,
            32 => 3,
            24 => 4,
            _ => {
                return Err(StorageError::Unsupported(format!(
                    "unsupported subtree depth {depth}"
                )));
            },
        };
        depth_buckets[bucket_index].push((original_index, node_index));
    }

    Ok(depth_buckets)
}

pub(crate) fn read_depth24_entries(
    iter: impl Iterator<Item = Result<(Box<[u8]>, Box<[u8]>), RocksDbError>>,
) -> Result<Vec<(u64, Word)>, StorageError> {
    let mut hashes = Vec::new();
    for item in iter {
        let (key_bytes, value_bytes) = item.map_err(map_rocksdb_err)?;
        let index = index_from_key_bytes(&key_bytes)?;
        let hash = Word::read_from_bytes(&value_bytes)?;
        hashes.push((index, hash));
    }
    Ok(hashes)
}

pub(crate) fn index_from_key_bytes(key_bytes: &[u8]) -> Result<u64, StorageError> {
    if key_bytes.len() != 8 {
        return Err(StorageError::BadKeyLen { expected: 8, found: key_bytes.len() });
    }
    let mut arr = [0u8; 8];
    arr.copy_from_slice(key_bytes);
    Ok(u64::from_be_bytes(arr))
}
