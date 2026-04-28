use std::hash::Hash;
use std::num::NonZeroUsize;
use std::sync::Arc;

use lru::LruCache as InnerCache;
use tokio::sync::{Mutex, MutexGuard};
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
    pub async fn get(&self, key: &K) -> Option<V> {
        self.lock().await.get(key).cloned()
    }

    /// Retrieves multiple values from the cache.
    ///
    /// Returns a vector of the same length as `keys`, where each element is `Some(value)` if the
    /// key was found in the cache, or `None` if it was not.
    pub async fn get_many<I>(&self, keys: I) -> Vec<Option<V>>
    where
        I: IntoIterator<Item = K>,
    {
        let mut cache = self.lock().await;
        keys.into_iter().map(|key| cache.get(&key).cloned()).collect()
    }

    /// Puts a value into the cache.
    pub async fn put(&self, key: K, value: V) {
        self.lock().await.put(key, value);
    }

    /// Puts multiple values into the cache.
    pub async fn put_many<I>(&self, entries: I)
    where
        I: IntoIterator<Item = (K, V)>,
    {
        let mut cache = self.lock().await;
        for (key, value) in entries {
            cache.put(key, value);
        }
    }

    #[instrument(name = "lru.lock", skip_all)]
    async fn lock(&self) -> MutexGuard<'_, InnerCache<K, V>> {
        self.0.lock().await
    }
}
