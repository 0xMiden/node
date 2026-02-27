use miden_crypto::merkle::smt::{MAX_LEAF_ENTRIES, SmtLeaf, SmtLeafError};
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
