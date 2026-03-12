//! Procedural macro for tracing without(?) papercuts
//!
//! Provides `#[instrument]` in the spirit of `tracing::instrument`, `trace/debug/info/warn/error`
//! in the spirit of `tracing::log`.
//!
//! There are however significant difference in argument parsing as well as interpretation.
//!
//! 1. `ErrorReport` is a first class citizens
//! 2. `target=` is implicitly assumed if not provided by the user
//! 3.
//! to capture the full error chain in tracing spans, rather than just the `Display` output.
//!
//! **Note**: This crate should not be used directly. Use `miden-node-tracing` instead,
//! which re-exports this macro along with all required dependencies.
//!
//! # Problem
//!
//! The standard `#[instrument(err)]` from `tracing` uses `Display` or `Debug` to format errors
//! in span events. This loses the error chain context, showing only the top-level error message.
//!
//! # Solution
//!
//! This macro wraps functions that return `Result<T, E>` and:
//! 1. Creates a tracing span with the configured attributes (delegating to `tracing::instrument`)
//! 2. On error, records the full error chain using `ErrorReport::as_report()`
//! 3. Sets the OpenTelemetry span status to error with the full report

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;

mod allowed;
mod instrument;
mod log;

#[cfg(test)]
mod tests;

#[proc_macro_attribute]
pub fn instrument(attr: TokenStream, item: TokenStream) -> TokenStream {
    instrument::instrument2(TokenStream2::from(attr), TokenStream2::from(item))
}

#[proc_macro]
pub fn error(ts: TokenStream) -> TokenStream {
    log::parse("error", ts.into()).into()
}

#[proc_macro]
pub fn warn(ts: TokenStream) -> TokenStream {
    log::parse("warn", ts.into()).into()
}

#[proc_macro]
pub fn info(ts: TokenStream) -> TokenStream {
    log::parse("info", ts.into()).into()
}

#[proc_macro]
pub fn debug(ts: TokenStream) -> TokenStream {
    log::parse("debug", ts.into()).into()
}

#[proc_macro]
pub fn trace(ts: TokenStream) -> TokenStream {
    log::parse("trace", ts.into()).into()
}
