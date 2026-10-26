//! Shared retry/backoff helpers built on top of the [`backon`] crate.
//!
//! These constructors give the node a single definition of the "standard" backoff schedules so
//! that retry behaviour stays consistent across components instead of being re-derived at each call
//! site. Use them together with the [`Retryable`] suffix extension, e.g.
//!
//! ```ignore
//! use miden_node_utils::retry::{self, Retryable};
//! use miden_node_tracing::warn;
//!
//! let value = (|| async { do_thing().await })
//!     .retry(retry::exponential(min, max))
//!     .when(|err| is_transient(err))
//!     .notify(|err, dur| {
//!         warn!(
//!             err,
//!             "retrying",
//!             retry.delay_ms = dur
//!         );
//!     })
//!     .await?;
//! ```

use std::error::Error as _;
use std::time::Duration;

pub use backon::{BackoffBuilder, Retryable, RetryableWithContext};
use backon::{ConstantBuilder, ExponentialBuilder};

// BACKOFF BUILDERS
// ================================================================================================

/// Builds an exponential backoff schedule that retries indefinitely.
///
/// Delays start at `min`, double on each attempt (factor `2.0`), are capped at `max`, and have
/// jitter applied to spread out concurrent retriers.
pub fn exponential(min: Duration, max: Duration) -> ExponentialBuilder {
    ExponentialBuilder::default()
        .with_min_delay(min)
        .with_max_delay(max)
        .with_factor(2.0)
        .with_jitter()
        .without_max_times()
}

/// Same as [`exponential`], but stops after `max_times` retries (i.e. `max_times + 1` total
/// attempts).
pub fn exponential_bounded(min: Duration, max: Duration, max_times: usize) -> ExponentialBuilder {
    exponential(min, max).with_max_times(max_times)
}

/// Builds a constant-delay backoff schedule.
///
/// `max_times` bounds the number of retries; pass `None` to retry indefinitely.
pub fn constant(delay: Duration, max_times: Option<usize>) -> ConstantBuilder {
    let builder = ConstantBuilder::default().with_delay(delay);
    match max_times {
        Some(max_times) => builder.with_max_times(max_times),
        None => builder.without_max_times(),
    }
}

/// Identifies service unavailability and local transport failures for retryable gRPC calls.
///
/// Tonic can report connection closures as cancelled, internal, or unknown errors. Requiring a
/// transport error in their source chain avoids retrying application errors with those codes.
pub fn is_retryable_grpc_error(status: &tonic::Status) -> bool {
    match status.code() {
        tonic::Code::Unavailable => true,
        tonic::Code::Cancelled | tonic::Code::Internal | tonic::Code::Unknown => {
            let mut source = status.source();
            while let Some(error) = source {
                if error.is::<tonic::transport::Error>() {
                    return true;
                }
                source = error.source();
            }
            false
        },
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::is_retryable_grpc_error;

    #[test]
    fn application_errors_are_not_connection_failures() {
        for code in [
            tonic::Code::Cancelled,
            tonic::Code::Internal,
            tonic::Code::Unknown,
            tonic::Code::InvalidArgument,
            tonic::Code::PermissionDenied,
            tonic::Code::DeadlineExceeded,
        ] {
            assert!(
                !is_retryable_grpc_error(&tonic::Status::new(code, "connection closed")),
                "{code:?}"
            );
        }
        assert!(is_retryable_grpc_error(&tonic::Status::unavailable("reconnecting")));
    }
}
