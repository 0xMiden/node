mod ban;
mod block;
mod proof;
mod stream;

pub(super) use ban::IpBanList;

/// Maximum number of concurrent block or proof subscriptions served by this RPC instance.
pub(super) const MAX_REPLICA_SUBSCRIPTIONS: usize = 10;
