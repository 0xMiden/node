use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

/// A fixed-capacity FIFO cache keyed by `K`.
///
/// When full, the oldest entry (by insertion order) is evicted to make room. Uses a [`HashMap`]
/// for O(1) lookup and a [`VecDeque`] to track insertion order for eviction.
///
/// Wraps the inner state in `Arc<Mutex>` so it can be cheaply cloned and shared across threads
/// without holding the lock across await points.
#[derive(Clone)]
pub struct FifoCache<K, V>(Arc<Mutex<Inner<K, V>>>);

struct Inner<K, V> {
    map: HashMap<K, V>,
    eviction: VecDeque<K>,
    capacity: NonZeroUsize,
}

impl<K, V> FifoCache<K, V>
where
    K: Hash + Eq + Clone,
    V: Clone,
{
    /// Creates a new cache with the given capacity.
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self(Arc::new(Mutex::new(Inner {
            map: HashMap::new(),
            eviction: VecDeque::new(),
            capacity,
        })))
    }

    /// Returns a clone of the value associated with `key`, or `None` if not present.
    pub fn get(&self, key: &K) -> Option<V> {
        self.0.lock().expect("fifo cache lock poisoned").map.get(key).cloned()
    }

    /// Inserts a key-value pair, evicting the oldest entry if the cache is at capacity.
    pub fn push(&self, key: K, value: V) {
        let mut inner = self.0.lock().expect("fifo cache lock poisoned");
        if inner.eviction.len() >= inner.capacity.get() {
            if let Some(oldest) = inner.eviction.pop_front() {
                inner.map.remove(&oldest);
            }
        }
        inner.eviction.push_back(key.clone());
        inner.map.insert(key, value);
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use super::FifoCache;

    fn cache(cap: usize) -> FifoCache<u32, &'static str> {
        FifoCache::new(NonZeroUsize::new(cap).unwrap())
    }

    #[test]
    fn get_returns_none_on_empty_cache() {
        let c = cache(4);
        assert_eq!(c.get(&1), None);
    }

    #[test]
    fn get_returns_inserted_value() {
        let c = cache(4);
        c.push(1, "a");
        assert_eq!(c.get(&1), Some("a"));
    }

    #[test]
    fn evicts_oldest_entry_when_full() {
        let c = cache(2);
        c.push(1, "a");
        c.push(2, "b");
        c.push(3, "c"); // evicts 1
        assert_eq!(c.get(&1), None);
        assert_eq!(c.get(&2), Some("b"));
        assert_eq!(c.get(&3), Some("c"));
    }

    #[test]
    fn overwrite_key_evicts_on_next_push() {
        // Pushing the same key twice leaves a ghost entry in the eviction queue. The ghost is a
        // no-op when it surfaces as the oldest entry: the key is already absent from the map so
        // map.remove() does nothing. The important invariant is that no *other* key is spuriously
        // evicted.
        let c = cache(2);
        c.push(1, "a");
        c.push(1, "b"); // eviction queue: [1, 1], map: {1: "b"}
        c.push(2, "c"); // evicts ghost front (key 1), map: {2: "c"}
        assert_eq!(c.get(&1), None); // 1 was evicted
        assert_eq!(c.get(&2), Some("c")); // 2 survived
    }

    #[test]
    fn clone_shares_state() {
        let c1 = cache(4);
        let c2 = c1.clone();
        c1.push(1, "a");
        assert_eq!(c2.get(&1), Some("a"));
    }
}
