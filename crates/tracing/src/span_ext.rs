use opentelemetry::trace::Status;

use crate::{ErrorReport, FailureClass};

/// Extension helper for marking the current OpenTelemetry span as failed.
pub trait ErrorSpanExt: private::Sealed {
    /// Marks the span as failed by `err`, recorded as a fault of kind `unclassified`.
    fn set_error(&self, err: &dyn std::error::Error);

    /// Records `failure` on the span and marks it as failed by `err`, unless the failure is a
    /// rejection.
    fn set_failure(&self, failure: FailureClass, err: &dyn std::error::Error);
}

impl ErrorSpanExt for tracing::Span {
    fn set_error(&self, err: &dyn std::error::Error) {
        self.set_failure(FailureClass::of_failed_span(None), err);
    }

    fn set_failure(&self, failure: FailureClass, err: &dyn std::error::Error) {
        failure.record(self);
        if !failure.is_rejection() {
            tracing_opentelemetry::OpenTelemetrySpanExt::set_status(
                self,
                Status::Error { description: err.as_report().into() },
            );
        }
    }
}

mod private {
    pub trait Sealed {}
    impl Sealed for tracing::Span {}
}
