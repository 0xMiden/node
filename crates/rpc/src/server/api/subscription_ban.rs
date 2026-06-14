use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How long a slow subscriber is banned from re-subscribing after being disconnected.
const BAN_DURATION: Duration = Duration::from_mins(10);

/// Maximum number of banned clients tracked at once.
const BAN_CAPACITY: usize = 100;

/// A bounded, time-based ban list keyed by client IP.
///
/// Subscribers that are disconnected for being too slow are temporarily banned from re-subscribing.
/// Entries are a simple FIFO queue of `(ip, expiry)` pairs. Because every ban uses the same fixed
/// [`BAN_DURATION`], entries are naturally ordered by expiry, so the most recent ban for an IP is
/// the last matching entry. Expired entries are not actively pruned; they are simply ignored on
/// lookup and eventually evicted once the queue reaches capacity.
#[derive(Debug)]
pub struct SubscriptionBan {
    banned: Mutex<VecDeque<(IpAddr, Instant)>>,
    duration: Duration,
    capacity: usize,
}

impl Default for SubscriptionBan {
    fn default() -> Self {
        Self::new(BAN_DURATION, BAN_CAPACITY)
    }
}

impl SubscriptionBan {
    fn new(duration: Duration, capacity: usize) -> Self {
        Self {
            banned: Mutex::new(VecDeque::new()),
            duration,
            capacity,
        }
    }

    /// Bans `ip` for [`BAN_DURATION`] starting now.
    ///
    /// If the list is at capacity, the oldest entry is evicted first.
    pub fn ban(&self, ip: IpAddr) {
        let expiry = Instant::now() + self.duration;
        let mut banned = self
            .banned
            .lock()
            .expect("ban mutex should not be poisoned");
        if banned.len() == self.capacity {
            banned.pop_front();
        }
        banned.push_back((ip, expiry));
    }

    /// Returns the remaining ban duration for `ip`, or `None` if it is not currently banned.
    pub fn remaining(&self, ip: IpAddr) -> Option<Duration> {
        let now = Instant::now();
        let banned = self
            .banned
            .lock()
            .expect("ban mutex should not be poisoned");
        // Entries are ordered by expiry, so the last match is the most recent (longest-lived) ban.
        banned
            .iter()
            .rev()
            .find(|(banned_ip, _)| *banned_ip == ip)
            .map(|(_, expiry)| expiry.saturating_duration_since(now))
            .filter(|remaining| !remaining.is_zero())
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, n))
    }

    #[test]
    fn unknown_ip_is_not_banned() {
        let ban = SubscriptionBan::default();
        assert!(ban.remaining(ip(1)).is_none());
    }

    #[test]
    fn banned_ip_reports_remaining_time() {
        let ban = SubscriptionBan::new(Duration::from_secs(600), 16);
        ban.ban(ip(1));

        let remaining = ban.remaining(ip(1)).expect("ip should be banned");
        assert!(remaining <= Duration::from_secs(600));
        assert!(ban.remaining(ip(2)).is_none());
    }

    #[test]
    fn expired_ban_is_ignored() {
        // A zero-length ban is already expired by the time it is queried.
        let ban = SubscriptionBan::new(Duration::ZERO, 16);
        ban.ban(ip(1));
        assert!(ban.remaining(ip(1)).is_none());
    }

    #[test]
    fn most_recent_ban_wins_over_stale_entry() {
        let ban = SubscriptionBan::new(Duration::from_secs(600), 16);
        let now = Instant::now();
        {
            let mut banned = ban.banned.lock().unwrap();
            // A stale, already-expired entry followed by a fresh, live ban for the same IP. The
            // live entry must take precedence over the leftover stale one.
            banned.push_back((ip(1), now));
            banned.push_back((ip(1), now + Duration::from_secs(600)));
        }
        assert!(ban.remaining(ip(1)).is_some());
    }

    #[test]
    fn oldest_entry_is_evicted_at_capacity() {
        let ban = SubscriptionBan::new(Duration::from_secs(600), 2);
        ban.ban(ip(1));
        ban.ban(ip(2));
        ban.ban(ip(3));

        // The first ban was evicted to make room for the third.
        assert!(ban.remaining(ip(1)).is_none());
        assert!(ban.remaining(ip(2)).is_some());
        assert!(ban.remaining(ip(3)).is_some());
    }
}
