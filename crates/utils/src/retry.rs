//! Shared retry/backoff helpers built on top of the [`backon`] crate.
//!
//! These constructors give the node a single definition of the "standard" backoff schedules so
//! that retry behaviour stays consistent across components instead of being re-derived at each call
//! site. Use them together with the [`Retryable`] suffix extension, e.g.
//!
//! ```ignore
//! use miden_node_utils::retry::{self, Retryable};
//!
//! let value = (|| async { do_thing().await })
//!     .retry(retry::exponential(min, max))
//!     .when(|err| is_transient(err))
//!     .notify(|err, dur| tracing::warn!(?dur, %err, "retrying"))
//!     .await?;
//! ```

use std::time::Duration;

pub use backon::{BackoffBuilder, Retryable};
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
