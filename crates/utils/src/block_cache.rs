use std::collections::VecDeque;
use std::num::NonZeroUsize;
use std::sync::{Arc, RwLock};

use miden_protocol::block::BlockNumber;

/// A cheaply cloneable block-ordered cache.
#[derive(Clone)]
pub struct BlockOrderedCache<T> {
    inner: Arc<RwLock<Inner<T>>>,
}

struct Inner<T> {
    fifo: VecDeque<T>,
    youngest: Option<BlockNumber>,
    capacity: usize,
}

impl<T> BlockOrderedCache<T> {
    /// Creates a new cache with the given capacity.
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(Inner {
                fifo: VecDeque::new(),
                youngest: None,
                capacity: capacity.get(),
            })),
        }
    }

    /// Pushes a new value into the cache and evicts the oldest value if the cache is full.
    ///
    /// # Error
    ///
    /// Returns the value if the provided block number is not the next in sequence.
    pub fn push(&self, number: BlockNumber, value: T) -> Result<(), T> {
        let mut inner = self.inner.write().expect("block cache lock poisoned");

        if let Some(youngest) = inner.youngest {
            if youngest.child() != number {
                return Err(value);
            }
        }

        if inner.fifo.len() >= inner.capacity {
            inner.fifo.pop_front();
        }

        inner.fifo.push_back(value);
        inner.youngest = Some(number);

        Ok(())
    }
}

impl<T: Clone> BlockOrderedCache<T> {
    /// Retrieves the value associated with the given block number from the cache.
    pub fn get(&self, number: BlockNumber) -> Option<T> {
        let inner = self.inner.read().expect("block cache lock poisoned");
        let youngest = inner.youngest?;
        let distance_to_oldest = u32::try_from(inner.fifo.len().checked_sub(1)?).ok()?;
        let oldest = youngest.checked_sub(distance_to_oldest)?;

        let offset = number.checked_sub(oldest.as_u32())?;
        inner.fifo.get(offset.as_usize()).cloned()
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
        assert_eq!(c.push(1.into(), "a"), Ok(()));
        assert_eq!(c.get(1.into()), Some("a"));
    }

    #[test]
    fn evicts_oldest_entry_when_full() {
        let c = cache(2);
        assert_eq!(c.push(5.into(), "a"), Ok(()));
        assert_eq!(c.push(6.into(), "b"), Ok(()));
        assert_eq!(c.push(7.into(), "c"), Ok(())); // evicts 5
        assert_eq!(c.get(5.into()), None);
        assert_eq!(c.get(6.into()), Some("b"));
        assert_eq!(c.get(7.into()), Some("c"));
    }

    #[test]
    fn overwrite_key_returns_value() {
        let c = cache(2);
        assert_eq!(c.push(1.into(), "a"), Ok(()));
        assert_eq!(c.push(1.into(), "b"), Err("b"));
        assert_eq!(c.get(1.into()), Some("a"));
    }

    #[test]
    fn parent_returns_value() {
        let c = cache(2);
        assert_eq!(c.push(3.into(), "a"), Ok(()));
        assert_eq!(c.push(2.into(), "b"), Err("b"));
        assert_eq!(c.get(3.into()), Some("a"));
    }

    #[test]
    fn wrong_child_returns_value() {
        let c = cache(2);
        assert_eq!(c.push(1.into(), "a"), Ok(()));
        assert_eq!(c.push(3.into(), "b"), Err("b"));
        assert_eq!(c.get(1.into()), Some("a"));
    }

    #[test]
    fn clone_shares_state() {
        let c1 = cache(4);
        let c2 = c1.clone();
        assert_eq!(c1.push(1.into(), "a"), Ok(()));
        assert_eq!(c2.get(1.into()), Some("a"));
    }
}
