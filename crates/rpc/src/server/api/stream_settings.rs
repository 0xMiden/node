//! Shared resource bounds for server-streaming RPC responses.

use std::num::NonZeroUsize;
use std::time::Duration;

/// Database rows fetched per page for compact synchronization records. This bounds internal work
/// and memory independently of encoded message size.
pub(super) const DB_PAGE_SIZE: NonZeroUsize = NonZeroUsize::new(256).unwrap();

/// Stream items queued before backpressure pauses the producer.
pub(super) const STREAM_BUFFER_SIZE: usize = 32;

/// Maximum time a producer waits for a stalled client to accept one update.
pub(super) const SEND_TIMEOUT: Duration = Duration::from_secs(10);
