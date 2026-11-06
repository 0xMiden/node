use std::time::Duration;

use miden_node_tracing::warn_v2;

mod prover;
mod rpc;

pub use prover::RemoteTransactionProver;
pub(crate) use rpc::BlockSubscriptionEvent;
pub use rpc::{RpcClient, RpcError};

/// Emits a structured warning for a transient NTX request failure that is about to be retried.
pub(crate) fn log_transient_retry<E: std::error::Error + 'static>(
    operation: &'static str,
    err: &E,
    sleep: Duration,
) {
    warn_v2!(
        err,
        "ntx transient request failure; retrying after backoff",
        operation.name = operation,
        retry.delay_ms = sleep
    );
}
