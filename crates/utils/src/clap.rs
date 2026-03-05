//! Public module for share clap pieces to reduce duplication

use std::time::Duration;
use std::u64;

const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_MAX_CONNECTION_AGE: Duration = Duration::from_mins(30);
const DEFAULT_REPLENISH_PER_SEC: u64 = 16;
const DEFAULT_BURST_SIZE: u64 = 128;
const DEFAULT_MAX_GLOBAL_CONNECTIONS: u64 = 1_000;

// Formats a Duration into a human-readable string for display in clap help text
// and yields a &'static str by _leaking_ the string deliberately.
pub fn duration_to_human_readable_string(duration: Duration) -> &'static str {
    Box::new(humantime::format_duration(duration).to_string()).leak()
}

#[derive(clap::Args, Copy, Clone, Debug, PartialEq, Eq)]
pub struct GrpcOptions {
    /// Maximum duration a gRPC request is allocated before being dropped by the server.
    ///
    /// This may occur if the server is overloaded or due to an internal bug.
    #[arg(
        long = "grpc.timeout",
        default_value = duration_to_human_readable_string(DEFAULT_REQUEST_TIMEOUT),
        value_parser = humantime::parse_duration,
        value_name = "DURATION"
    )]
    pub request_timeout: Duration,

    /// Maximum duration of a connection before we drop it on the server side irrespective of
    /// activity.
    #[arg(
        long = "grpc.max_connection_age",
        default_value = duration_to_human_readable_string(DEFAULT_MAX_CONNECTION_AGE),
        value_parser = humantime::parse_duration,
        value_name = "MAX_CONNECTION_AGE"
    )]
    pub max_connection_age: Duration,

    /// Number of connections to be served before the "API tokens" need to be replenished
    /// per IP address.
    #[arg(
        long = "grpc.max_connection_age",
        default_value_t = DEFAULT_BURST_SIZE,
        value_name = "BURST_SIZE"
    )]
    pub burst_size: u64,

    /// Number of requests to unlock per second.
    #[arg(
        long = "grpc.replenish_per_sec",
        default_value_t = DEFAULT_REPLENISH_PER_SEC,
        value_name = "REPLENISH_PER_SEC"
    )]
    pub replenish_per_sec: u64,

    /// Number of global concurrent connections.
    #[arg(
        long = "grpc.max_global_connections",
        default_value_t = DEFAULT_MAX_GLOBAL_CONNECTIONS,
        value_name = "MAX_GLOBAL_CONNECTIONS"
    )]
    pub max_global_concurrent_connections: u64,
}

impl Default for GrpcOptions {
    fn default() -> Self {
        Self {
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            max_connection_age: DEFAULT_MAX_CONNECTION_AGE,
            burst_size: DEFAULT_BURST_SIZE,
            replenish_per_sec: DEFAULT_REPLENISH_PER_SEC,
            max_global_concurrent_connections: DEFAULT_MAX_GLOBAL_CONNECTIONS,
        }
    }
}

impl GrpcOptions {
    /// Return a gRPC config for benchmarking.
    pub fn bench() -> Self {
        Self {
            request_timeout: Duration::from_hours(24),
            max_connection_age: Duration::from_hours(24),
            burst_size: u64::MAX,
            replenish_per_sec: u64::MAX,
            max_global_concurrent_connections: u64::MAX,
        }
    }
}
