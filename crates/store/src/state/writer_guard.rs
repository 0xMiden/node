use std::cell::UnsafeCell;

/// A single-writer / multi-reader wrapper that provides lock-free access to shared state.
///
/// This type enables a pattern where one dedicated writer task mutates data while many reader
/// tasks concurrently access it, without any locks.
///
/// # Safety Contract
///
/// 1. **Single writer**: Only one task (the writer, serialized by a channel) may call
///    [`as_mut()`](Self::as_mut). This invariant is enforced architecturally, not by the type
///    system.
/// 2. **Publish barrier**: After completing all mutations, the writer performs an `ArcSwap::store`
///    on the shared in-memory state, which includes a `Release` memory barrier.
/// 3. **Subscribe barrier**: Before calling [`as_ref()`](Self::as_ref), readers perform an
///    `ArcSwap::load_full` which includes an `Acquire` memory barrier.
/// 4. The barrier pair establishes a *happens-before* relationship, guaranteeing that all mutations
///    performed before the store are visible to any reader that observes the updated state.
///
/// Because the wrapped data structures are append-only or overlay-based (keyed by block number),
/// readers that observe an older state will simply query at that older block number, which is
/// safe.
pub struct WriterGuard<T> {
    inner: UnsafeCell<T>,
}

// SAFETY: The single-writer invariant is enforced by the channel-based writer task architecture.
// Readers only call `as_ref()` which returns `&T`. The writer completes all mutations before
// performing an `ArcSwap::store` (which includes a Release barrier), and readers perform an
// `ArcSwap::load_full` (which includes an Acquire barrier) before accessing the data.
// This guarantees no data races.
unsafe impl<T: Send + Sync> Send for WriterGuard<T> {}
unsafe impl<T: Send + Sync> Sync for WriterGuard<T> {}

impl<T> WriterGuard<T> {
    /// Creates a new `WriterGuard` wrapping the given value.
    pub fn new(value: T) -> Self {
        Self { inner: UnsafeCell::new(value) }
    }

    /// Returns a shared reference to the wrapped value.
    ///
    /// Safe for any reader thread. The data is guaranteed to be in a consistent state because
    /// the caller accesses shared state through `ArcSwap::load_full` (which includes an
    /// `Acquire` barrier), establishing a happens-before relationship with the writer's
    /// `ArcSwap::store` (which includes a `Release` barrier).
    pub(super) fn as_ref(&self) -> &T {
        // SAFETY: The writer completes all mutations before the ArcSwap::store (Release barrier).
        // The reader performs ArcSwap::load_full (Acquire barrier) before calling this.
        // The barrier pair ensures all writes are visible.
        unsafe { &*self.inner.get() }
    }

    /// Returns an exclusive mutable reference to the wrapped value.
    ///
    /// # Safety
    ///
    /// Must only be called from the single writer task. The caller must ensure:
    /// - No other calls to `as_mut()` are concurrent (enforced by channel serialization).
    /// - All mutations through the returned reference are completed before performing an
    ///   `ArcSwap::store` on the shared in-memory state.
    #[expect(clippy::mut_from_ref)]
    pub unsafe fn as_mut(&self) -> &mut T {
        unsafe { &mut *self.inner.get() }
    }
}
