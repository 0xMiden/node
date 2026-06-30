use std::time::Instant;

use miden_node_store::state::StreamError;
use tonic::Status;

mod ban;
mod block;
mod proof;

pub(super) use ban::IpBanList;

/// Maximum number of concurrent block or proof subscriptions served by this RPC instance.
pub(super) const MAX_REPLICA_SUBSCRIPTIONS: usize = 10;

/// Maximum gap between tip and subscriber's requested starting block where the starting block is
/// greater than the tip.
const MAX_FUTURE_GAP_IN_SUBSCRIPTIONS: u32 = 100u32;

fn stream_error_to_status(err: StreamError) -> Status {
    let code = match err {
        StreamError::ServerShutdown => tonic::Code::Unavailable,
        StreamError::ConnectionClosed => tonic::Code::Aborted,
        StreamError::SlowSubscriber => tonic::Code::ResourceExhausted,
        StreamError::Internal => tonic::Code::Internal,
    };

    Status::new(code, err.to_string())
}

/// Builds the status returned to a client that is temporarily banned from subscribing for having
/// previously been disconnected as too slow.
fn subscription_ban_status(until: Instant) -> Status {
    let remaining = until.saturating_duration_since(Instant::now());
    Status::resource_exhausted(format!(
        "temporarily banned from subscribing for being too slow; retry in {} seconds",
        // Round up so the reported wait never undershoots the actual remaining ban.
        remaining.as_secs() + 1,
    ))
}
