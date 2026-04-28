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

    /// Puts a value into the cache.
    pub async fn put(&self, key: K, value: V) {
        self.lock().await.put(key, value);
    }

    #[instrument(name = "lru.lock", skip_all)]
    async fn lock(&self) -> MutexGuard<'_, InnerCache<K, V>> {
        self.0.lock().await
    }
}
