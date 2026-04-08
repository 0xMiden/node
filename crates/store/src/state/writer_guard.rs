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
/// 2. **Publish barrier**: After completing all mutations, the writer performs an atomic store with
///    [`Release`](std::sync::atomic::Ordering::Release) ordering on a shared block counter.
/// 3. **Subscribe barrier**: Before calling [`as_ref()`](Self::as_ref), readers perform an atomic
///    load with [`Acquire`](std::sync::atomic::Ordering::Acquire) ordering on the same counter.
/// 4. The `Release`/`Acquire` pair establishes a *happens-before* relationship, guaranteeing that
///    all mutations performed before the `Release` store are visible to any reader that observes
///    the updated counter value.
///
/// Because the wrapped data structures are append-only or overlay-based (keyed by block number),
/// readers that observe an older counter value will simply query at that older block number,
/// which is safe.
pub struct WriterGuard<T> {
    inner: UnsafeCell<T>,
}

// SAFETY: The single-writer invariant is enforced by the channel-based writer task architecture.
// Readers only call `as_ref()` which returns `&T`. The writer completes all mutations before
// advancing the atomic block counter (`Release`), and readers load the counter (`Acquire`)
// before accessing the data. This guarantees no data races.
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
    /// the caller must have loaded the atomic block counter with `Acquire` ordering before
    /// calling this method, establishing a happens-before relationship with the writer's
    /// `Release` store.
    pub(super) fn as_ref(&self) -> &T {
        // SAFETY: The writer completes all mutations before the Release store on the block
        // counter. The reader loads the counter with Acquire before calling this. The
        // Acquire/Release pair ensures all writes are visible.
        unsafe { &*self.inner.get() }
    }

    /// Returns an exclusive mutable reference to the wrapped value.
    ///
    /// # Safety
    ///
    /// Must only be called from the single writer task. The caller must ensure:
    /// - No other calls to `as_mut()` are concurrent (enforced by channel serialization).
    /// - All mutations through the returned reference are completed before performing a `Release`
    ///   store on the shared block counter.
    #[expect(clippy::mut_from_ref)]
    pub unsafe fn as_mut(&self) -> &mut T {
        unsafe { &mut *self.inner.get() }
    }
}
