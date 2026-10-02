use opentelemetry::trace::Status;

use crate::ErrorReport;

/// Extension helper for marking the current OpenTelemetry span as failed.
pub trait ErrorSpanExt: private::Sealed {
    fn set_error(&self, err: &dyn std::error::Error);
}

impl<S> ErrorSpanExt for S
where
    S: tracing_opentelemetry::OpenTelemetrySpanExt,
{
    fn set_error(&self, err: &dyn std::error::Error) {
        tracing_opentelemetry::OpenTelemetrySpanExt::set_status(
            self,
            Status::Error { description: err.as_report().into() },
        );
    }
}

mod private {
    pub trait Sealed {}
    impl<S> Sealed for S where S: tracing_opentelemetry::OpenTelemetrySpanExt {}
}
