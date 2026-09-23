//! Miden node tracing conventions and OpenTelemetry integration.

extern crate self as miden_node_tracing;

mod attribute;
pub mod grpc;
mod instrument;
mod logging;
pub mod panic;
mod span_ext;
pub mod spawn;

#[doc(hidden)]
pub use attribute::field_name_allowed;
pub use attribute::{RecordAttribute, record_attribute};
#[cfg(feature = "testing")]
pub use logging::setup_test_tracing;
pub use logging::{
    OpenTelemetry,
    OtelGuard,
    ResourceConfig,
    TracingConfig,
    setup_tracing,
    setup_tracing_with_config,
};
pub use miden_node_tracing_macro::{
    debug,
    error,
    info,
    miden_instrument,
    miden_span_record,
    trace,
    warn,
};
pub use span_ext::ErrorSpanExt;
// Used directly by applications and by expansions of `tracing::instrument`.
pub use tracing::{Instrument, Level, Span, Value, enabled, field, info_span};
/// Upstream `tracing` exports required by generated macro code.
#[doc(hidden)]
pub use tracing::{event, if_log_enabled, level_enabled, span};

/// Upstream attribute and event macros used by this crate's proc-macro expansions.
#[doc(hidden)]
pub mod __private {
    pub use tracing::{debug, error, info, instrument, trace, warn};

    pub use crate::instrument::AsDynError;
}

/// Extends errors with a stable string representation of their source chain.
pub trait ErrorReport: std::error::Error {
    /// Returns a string representation of the error and its source chain.
    fn as_report(&self) -> String {
        use std::fmt::Write;
        let mut report = self.to_string();

        std::iter::successors(self.source(), |child| child.source())
            .for_each(|source| write!(report, "\ncaused by: {source}").unwrap());

        report
    }

    /// Creates a new root in the error chain and returns the complete error report.
    fn as_report_context(&self, context: &'static str) -> String {
        format!("{context}: \ncaused by: {}", self.as_report())
    }
}

impl<T: std::error::Error + ?Sized> ErrorReport for T {}

#[cfg(test)]
mod tests {
    use super::ErrorReport;

    #[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
    enum TestSourceError {
        #[error("source error")]
        Source,
    }

    #[derive(thiserror::Error, Debug)]
    enum TestError {
        #[error("parent error")]
        Parent(#[from] TestSourceError),
    }

    #[test]
    fn as_report() {
        let error = TestError::Parent(TestSourceError::Source);
        assert_eq!("parent error\ncaused by: source error", error.as_report());
    }

    #[test]
    fn as_report_context() {
        let error = TestError::Parent(TestSourceError::Source);
        assert_eq!(
            "final error: \ncaused by: parent error\ncaused by: source error",
            error.as_report_context("final error")
        );
    }
}
