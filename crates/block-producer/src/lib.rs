#![recursion_limit = "256"]
use std::num::NonZeroUsize;
use std::time::Duration;

#[cfg(test)]
pub mod test_utils;

mod batch_builder;
mod block_builder;
mod domain;
mod mempool;
mod remote_prover;
pub mod store;
mod validator;

#[cfg(feature = "testing")]
pub mod errors;
#[cfg(not(feature = "testing"))]
mod errors;

pub mod server;
pub use server::BlockProducer;

// CONSTANTS
// =================================================================================================

/// The name of the block producer component.
pub const COMPONENT: &str = "miden-block-producer";

/// The number of transactions per batch.
pub const DEFAULT_MAX_TXS_PER_BATCH: usize = 8;

/// Maximum number of batches per block.
pub const DEFAULT_MAX_BATCHES_PER_BLOCK: usize = 8;

/// Size of the batch building worker pool.
const SERVER_NUM_BATCH_BUILDERS: NonZeroUsize = NonZeroUsize::new(2).unwrap();

/// The number of blocks of committed state that the mempool retains.
///
/// This determines the grace period incoming transactions have between fetching their input from
/// the store and verification in the mempool.
const SERVER_MEMPOOL_STATE_RETENTION: NonZeroUsize = NonZeroUsize::new(5).unwrap();

/// Transactions are rejected by the mempool if there is less than this amount of blocks between the
/// chain tip and the transaction's expiration block.
///
/// This rejects transactions which would likely expire before making it into a block.
const SERVER_MEMPOOL_EXPIRATION_SLACK: u32 = 2;

/// The interval at which to update the cached mempool statistics.
const CACHED_MEMPOOL_STATS_UPDATE_INTERVAL: Duration = Duration::from_secs(5);

/// How often a block is created.
pub const DEFAULT_BLOCK_INTERVAL: Duration = Duration::from_secs(3);

/// How often a batch is created.
pub const DEFAULT_BATCH_INTERVAL: Duration = Duration::from_secs(1);

/// The default transaction capacity of the mempool.
///
/// The value is selected such that all transactions should approximately be processed within one
/// minutes with a block time of 5s.
#[allow(clippy::cast_sign_loss, reason = "Both durations are positive")]
pub const DEFAULT_MEMPOOL_TX_CAPACITY: NonZeroUsize = NonZeroUsize::new(
    DEFAULT_MAX_BATCHES_PER_BLOCK
        * DEFAULT_MAX_TXS_PER_BATCH
        * (Duration::from_secs(60).div_duration_f32(DEFAULT_BLOCK_INTERVAL)) as usize,
)
.unwrap();

const _: () = assert!(
    DEFAULT_MAX_BATCHES_PER_BLOCK <= miden_protocol::MAX_BATCHES_PER_BLOCK,
    "Server constraint cannot exceed the protocol's constraint"
);

const _: () = assert!(
    DEFAULT_MAX_TXS_PER_BATCH <= miden_protocol::MAX_ACCOUNTS_PER_BATCH,
    "Server constraint cannot exceed the protocol's constraint"
);

/// An extension trait used only locally to implement telemetry injection.
trait TelemetryInjectorExt {
    /// Inject [`tracing`] telemetry from self.
    fn inject_telemetry(&self);
}
