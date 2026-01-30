use std::num::NonZeroUsize;

mod actor;
mod block_producer;
mod coordinator;
mod producer;
mod store;

pub use producer::NetworkTransactionProducer;

// CONSTANTS
// =================================================================================================

const COMPONENT: &str = "miden-ntx-producer";

/// Maximum number of network notes a network transaction is allowed to consume.
const MAX_NOTES_PER_TX: NonZeroUsize = NonZeroUsize::new(20).unwrap();
const _: () = assert!(MAX_NOTES_PER_TX.get() <= miden_tx::MAX_NUM_CHECKER_NOTES);

/// Maximum number of network transactions which should be in progress concurrently.
///
/// This only counts transactions which are being computed locally and does not include
/// uncommitted transactions in the mempool.
const MAX_IN_PROGRESS_TXS: usize = 4;
