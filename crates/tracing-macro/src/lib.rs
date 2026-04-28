use proc_macro::TokenStream;

mod instrument;
mod level;
mod metadata;
mod span;
mod target;

/// Instruments a function with Miden tracing defaults.
///
/// This macro delegates span creation to `tracing::instrument`, but always applies `skip_all`,
/// requires an allowed target, rejects field and error recording options, and records returned
/// errors through `miden_node_tracing::Span::record_error`.
#[proc_macro_attribute]
pub fn instrument(attr: TokenStream, item: TokenStream) -> TokenStream {
    instrument::instrument(attr, item)
}

/// Creates a trace-level span with Miden tracing defaults.
#[proc_macro]
pub fn trace_span(input: TokenStream) -> TokenStream {
    span::trace_span(input)
}

/// Creates a debug-level span with Miden tracing defaults.
#[proc_macro]
pub fn debug_span(input: TokenStream) -> TokenStream {
    span::debug_span(input)
}

/// Creates an info-level span with Miden tracing defaults.
#[proc_macro]
pub fn info_span(input: TokenStream) -> TokenStream {
    span::info_span(input)
}

/// Creates a warn-level span with Miden tracing defaults.
#[proc_macro]
pub fn warn_span(input: TokenStream) -> TokenStream {
    span::warn_span(input)
}

/// Creates an error-level span with Miden tracing defaults.
#[proc_macro]
pub fn error_span(input: TokenStream) -> TokenStream {
    span::error_span(input)
}
