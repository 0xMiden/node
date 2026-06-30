use std::time::Instant;

use miden_protocol::block::BlockNumber;
use tonic::Status;

mod ban;
mod block;
mod proof;
mod stream;

pub(super) use ban::IpBanList;
use stream::StreamError;

/// Maximum number of concurrent block or proof subscriptions served by this RPC instance.
pub(super) const MAX_REPLICA_SUBSCRIPTIONS: usize = 10;

/// Maximum gap between tip and subscriber's requested starting block where the starting block is
/// greater than the tip.
const MAX_FUTURE_GAP_IN_SUBSCRIPTIONS: u32 = 100u32;

fn subscription_start_exceeds_future_gap(block_from: u32, chain_tip: BlockNumber) -> bool {
    block_from > chain_tip.as_u32().saturating_add(MAX_FUTURE_GAP_IN_SUBSCRIPTIONS)
}

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

#[cfg(test)]
mod tests {
    use miden_protocol::block::BlockNumber;

    use super::*;

    #[test]
    fn subscription_start_may_be_at_or_behind_chain_tip() {
        let chain_tip = BlockNumber::from(10u32);

        assert!(!subscription_start_exceeds_future_gap(0, chain_tip));
        assert!(!subscription_start_exceeds_future_gap(10, chain_tip));
    }

    #[test]
    fn subscription_start_may_be_within_future_gap() {
        let chain_tip = BlockNumber::from(10u32);

        assert!(!subscription_start_exceeds_future_gap(
            10 + MAX_FUTURE_GAP_IN_SUBSCRIPTIONS,
            chain_tip,
        ));
        assert!(subscription_start_exceeds_future_gap(
            10 + MAX_FUTURE_GAP_IN_SUBSCRIPTIONS + 1,
            chain_tip,
        ));
    }

    #[test]
    fn subscription_start_future_gap_check_saturates_at_max_block() {
        let chain_tip = BlockNumber::from(u32::MAX - 10);

        assert!(!subscription_start_exceeds_future_gap(u32::MAX, chain_tip));
    }
}
