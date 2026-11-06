pub mod child;
mod operations;

pub use operations::{configured, explicit_error, explicit_override, parent, root};

pub fn manual_spans() {
    let parent = miden_node_tracing::info_span_v2!("manual.parent", account.id = "account");
    let _guard = parent.enter();
    let _ = miden_node_tracing::trace_span_v2!("manual.trace");
    let _ = miden_node_tracing::debug_span_v2!("manual.debug");
    let _ = miden_node_tracing::warn_span_v2!(parent: &parent, "manual.warn");
    let _ = miden_node_tracing::error_span_v2!(parent: None, "manual.error");
    let _ = miden_node_tracing::info_span_v2!(target: "miden::explicit", "manual.override");
}
