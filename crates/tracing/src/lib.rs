//! Tracing and OpenTelemetry integration for Miden node.

// Proc macros expand to absolute `::miden_node_tracing::...` paths. This alias lets those
// expansions resolve when the macros are used inside this crate's own tests and examples.
extern crate self as miden_node_tracing;

mod catalog;
mod event;
mod exporter;
mod field;
mod filter;
#[expect(
    dead_code,
    reason = "control-plane filters are wired in once subscriber/exporter setup is added"
)]
mod internal;
mod object;
mod span;
mod user;

#[cfg(test)]
mod test_utils;

// Exposed so admin interfaces can enumerate telemetry declared through the macros without
// scraping source code or relying on runtime traffic to discover callsites.
pub use catalog::{
    EventMetadata,
    SpanLevel,
    SpanMetadata,
    TelemetryMetadata,
    registered_events,
    registered_metadata,
    registered_spans,
    registered_user_facing_metadata,
};
pub use event::Event;
pub use exporter::{
    DEFAULT_OTEL_FILTER,
    DEFAULT_USER_LOG_FILTER,
    ExportError,
    InstallError,
    TracingConfig,
    TracingHandle,
    install,
};
pub use field::OpenTelemetryField;
pub use filter::FilterError;
pub use miden_node_tracing_macro::{
    debug,
    debug_span,
    error,
    error_span,
    event,
    info,
    info_span,
    instrument,
    trace,
    trace_span,
    warn,
    warn_span,
};
pub use object::{OpenTelemetryObject, OpenTelemetryObjectRecorder};
pub use span::Span;

fn install_panic_hook() {
    static INSTALL: std::sync::Once = std::sync::Once::new();

    INSTALL.call_once(|| {
        let previous_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            internal::emit_panic(info);
            previous_hook(info);
        }));
    });
}

#[doc(hidden)]
pub mod __private {
    /// Re-exported for proc-macro expansions that submit span metadata to the crate-owned
    /// inventory registry.
    ///
    /// The generated `inventory::submit!` call is compiled in the downstream crate, so it
    /// needs a public path to the exact `inventory` crate used by `miden-node-tracing`.
    pub use inventory;
    /// Re-exported for proc-macro expansions that create and instrument spans/events.
    ///
    /// The generated code expands in the downstream crate and uses `tracing::instrument`,
    /// `tracing::*_span!`, `tracing::event_enabled!`, and `tracing::Level`. Keeping this under
    /// `__private` avoids requiring callers to depend on or import `tracing` directly.
    pub use tracing;

    /// Event recorder used by the event macros while building typed event attributes.
    ///
    /// This type is implementation detail rather than caller API, but generated event macro
    /// code must be able to construct it from downstream crates.
    pub use crate::event::OpenTelemetryEventRecorder;
}
