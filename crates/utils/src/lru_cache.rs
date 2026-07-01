use std::hash::Hash;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, MutexGuard};

use lru::LruCache as InnerCache;

/// A newtype wrapper around an LRU cache. Ensures that the cache lock is not held across await
/// points.
#[derive(Clone)]
pub struct LruCache<K, V>(Arc<Mutex<InnerCache<K, V>>>);

impl<K, V> LruCache<K, V>
where
    K: Hash + Eq,
    V: Clone,
{
    /// Creates a new cache with the given capacity.
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self(Arc::new(Mutex::new(InnerCache::new(capacity))))
    }

    /// Retrieves a value from the cache.
    pub fn get(&self, key: &K) -> Option<V> {
        self.lock().get(key).cloned()
    }

    /// Puts a value into the cache.
    pub fn put(&self, key: K, value: V) {
        self.lock().put(key, value);
    }

    /// Retrieves multiple values from the cache while holding the cache lock once.
    pub fn get_many<'a>(&self, keys: impl IntoIterator<Item = &'a K>) -> Vec<Option<V>>
    where
        K: 'a,
    {
        let mut cache = self.lock();
        keys.into_iter().map(|key| cache.get(key).cloned()).collect()
    }

    /// Puts multiple values into the cache while holding the cache lock once.
    pub fn put_many(&self, entries: impl IntoIterator<Item = (K, V)>) {
        let mut cache = self.lock();
        for (key, value) in entries {
            cache.put(key, value);
        }
    }

    /// Clears all entries from the cache.
    pub fn clear(&self) {
        self.lock().clear();
    }

    #[crate::tracing::miden_instrument(name = "lru.lock", skip_all)]
    fn lock(&self) -> MutexGuard<'_, InnerCache<K, V>> {
        // SAFETY: The mutex is only held for the duration of the get/put operation where panics are
        // possible only if we're running out of memory, in which case the entire process is likely
        // to be unstable anyway.
        self.0.lock().expect("LRU cache mutex poisoned")
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use super::LruCache;

    fn cache(cap: usize) -> LruCache<u32, &'static str> {
        LruCache::new(NonZeroUsize::new(cap).unwrap())
    }

    #[tokio::test]
    async fn get_returns_none_on_empty_cache() {
        let c = cache(4);
        assert_eq!(c.get(&1), None);
    }

    #[tokio::test]
    async fn get_returns_inserted_value() {
        let c = cache(4);
        c.put(1, "a");
        assert_eq!(c.get(&1), Some("a"));
    }

    #[tokio::test]
    async fn evicts_least_recently_used_when_full() {
        let c = cache(2);
        c.put(1, "a");
        c.put(2, "b");
        c.get(&1); // 1 is now most recently used
        c.put(3, "c"); // evicts 2 (least recently used)
        assert_eq!(c.get(&1), Some("a"));
        assert_eq!(c.get(&2), None);
        assert_eq!(c.get(&3), Some("c"));
    }

    #[tokio::test]
    async fn put_overwrites_existing_value() {
        let c = cache(4);
        c.put(1, "a");
        c.put(1, "b");
        assert_eq!(c.get(&1), Some("b"));
    }

    #[tokio::test]
    async fn clone_shares_state() {
        let c1 = cache(4);
        let c2 = c1.clone();
        c1.put(1, "a");
        assert_eq!(c2.get(&1), Some("a"));
    }
}
