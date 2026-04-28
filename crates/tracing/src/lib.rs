//! Tracing and OpenTelemetry integration for Miden node.

extern crate self as miden_node_tracing;

mod catalog;
mod field;
mod filter;
mod object;
mod span;

#[cfg(test)]
mod test_utils;

pub use catalog::{SpanLevel, SpanMetadata, registered_spans};
pub use field::OpenTelemetryField;
pub use filter::{DEFAULT_FILTER, DynamicFilter, DynamicFilterError, DynamicFilterLayer};
#[doc(hidden)]
pub use inventory;
pub use miden_node_tracing_macro::{
    debug_span,
    error_span,
    info_span,
    instrument,
    trace_span,
    warn_span,
};
pub use object::{OpenTelemetryObject, OpenTelemetryObjectRecorder};
pub use span::Span;
#[doc(hidden)]
pub use tracing;
