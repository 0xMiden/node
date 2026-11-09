pub mod child;
mod operations;

pub use operations::{configured, explicit_error, explicit_override, parent, root};

pub fn manual_spans() {
    let parent = miden_node_tracing::info_span!("manual.parent", account.id = "account");
    let _guard = parent.enter();
    let _ = miden_node_tracing::trace_span!("manual.trace");
    let _ = miden_node_tracing::debug_span!("manual.debug");
    let _ = miden_node_tracing::warn_span!(parent: &parent, "manual.warn");
    let _ = miden_node_tracing::error_span!(parent: None, "manual.error");
    let _ = miden_node_tracing::info_span!(target: "miden::explicit", "manual.override");
}
