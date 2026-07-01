pub mod grpc;
mod span_ext;

pub use miden_node_tracing_macro::{miden_instrument, miden_span_record};
pub use span_ext::{OpenTelemetrySpanExt, ToValue};
