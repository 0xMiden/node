use std::time::Instant;

use tonic::Status;

mod ban;
mod block;
mod proof;
mod stream;

pub(super) use ban::IpBanList;

/// Maximum number of concurrent block or proof subscriptions served by this RPC instance.
pub(super) const MAX_REPLICA_SUBSCRIPTIONS: usize = 10;

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
