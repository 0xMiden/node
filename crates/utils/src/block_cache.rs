use std::collections::VecDeque;
use std::num::NonZeroUsize;
use std::sync::{Arc, RwLock};

use miden_protocol::block::BlockNumber;

type BlockOrderedQueue<T> = VecDeque<(BlockNumber, T)>;

/// A cheaply cloneable block-ordered cache.
#[derive(Clone)]
pub struct BlockOrderedCache<T> {
    inner: Arc<RwLock<BlockOrderedQueue<T>>>,
    capacity: usize,
}

impl<T> BlockOrderedCache<T> {
    /// Creates a new cache with the given capacity.
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(VecDeque::new())),
            capacity: capacity.get(),
        }
    }

    /// Pushes a new value into the cache and evicts the oldest value if the cache is full.
    ///
    /// # Panics
    ///
    /// Panics if the provided block number is not a child of the youngest block in the cache.
    pub fn push(&self, number: BlockNumber, value: T) {
        let mut fifo = self.inner.write().expect("fifo cache lock poisoned");

        if let Some((youngest, _)) = fifo.back() {
            assert_eq!(youngest.child(), number);
        }

        if fifo.len() == self.capacity {
            fifo.pop_front();
        }

        fifo.push_back((number, value));
    }
}

impl<T: Clone> BlockOrderedCache<T> {
    /// Retrieves the value associated with the given block number from the cache.
    pub fn get(&self, number: BlockNumber) -> Option<T> {
        let fifo = self.inner.read().expect("fifo cache lock poisoned");
        let (oldest, _) = fifo.front()?;

        let offset = number.checked_sub(oldest.as_u32())?;
        let (_, value) = fifo.get(offset.as_usize())?;
        Some(value.clone())
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use super::BlockOrderedCache;

    fn cache(cap: usize) -> BlockOrderedCache<&'static str> {
        BlockOrderedCache::new(NonZeroUsize::new(cap).unwrap())
    }

    #[test]
    fn get_returns_none_on_empty_cache() {
        let c = cache(4);
        assert_eq!(c.get(1.into()), None);
    }

    #[test]
    fn get_returns_inserted_value() {
        let c = cache(4);
        c.push(1.into(), "a");
        assert_eq!(c.get(1.into()), Some("a"));
    }

    #[test]
    fn evicts_oldest_entry_when_full() {
        let c = cache(2);
        c.push(5.into(), "a");
        c.push(6.into(), "b");
        c.push(7.into(), "c"); // evicts 1
        assert_eq!(c.get(5.into()), None);
        assert_eq!(c.get(6.into()), Some("b"));
        assert_eq!(c.get(7.into()), Some("c"));
    }

    #[test]
    #[should_panic]
    fn overwrite_key_panics() {
        let c = cache(2);
        c.push(1.into(), "a");
        c.push(1.into(), "b");
    }

    #[test]
    #[should_panic]
    fn parent_panics() {
        let c = cache(2);
        c.push(3.into(), "a");
        c.push(2.into(), "b");
    }

    #[test]
    #[should_panic]
    fn wrong_child_panics() {
        let c = cache(2);
        c.push(1.into(), "a");
        c.push(3.into(), "b");
    }

    #[test]
    fn clone_shares_state() {
        let c1 = cache(4);
        let c2 = c1.clone();
        c1.push(1.into(), "a");
        assert_eq!(c2.get(1.into()), Some("a"));
    }
}
