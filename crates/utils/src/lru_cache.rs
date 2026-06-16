use std::hash::Hash;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, MutexGuard};

use lru::LruCache as InnerCache;
use tracing::instrument;

/// A newtype wrapper around an LRU cache. Ensures that the cache lock is not held across
/// await points.
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

    #[instrument(name = "lru.lock", skip_all)]
    fn lock(&self) -> MutexGuard<'_, InnerCache<K, V>> {
        // SAFETY: The mutex is only held for the duration of the get/put operation
        // where panics are possible only if we're running out of memory, in which
        // case the entire process is likely to be unstable anyway.
        self.0.lock().expect("LRU cache mutex poisoned")
    }
}
