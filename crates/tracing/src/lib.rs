//! Tracing utilities for Miden node with enhanced error reporting.
//!
//! This crate provides an `#[instrument_with_err_report]` attribute macro that enhances
//! the standard `tracing::instrument` with full error chain reporting.
//!
//! # Usage
//!
//! ```rust,ignore
//! use miden_node_tracing::instrument_with_err_report;
//!
//! #[instrument_with_err_report(target = "my_component", skip_all, err)]
//! async fn apply_block(&self, block: Block) -> Result<(), ApplyBlockError> {
//!     // ...
//! }
//! ```
//!
//! When an error occurs, the full error chain is recorded:
//! ```text
//! failed to apply block to store
//! caused by: database error
//! caused by: SQLite error: table 'blocks' has 10 columns but 9 values were supplied
//! ```

// Re-export the instrument macro
pub use miden_node_tracing_macro::instrument_with_err_report;
// Re-export ErrorReport from miden-node-utils
pub use miden_node_utils::ErrorReport;
// Re-export OpenTelemetrySpanExt from miden-node-utils
pub use miden_node_utils::tracing::OpenTelemetrySpanExt;
// Re-export OpenTelemetry types needed by the macro
pub use opentelemetry::trace::Status as OtelStatus;
pub use tracing::field::Empty as FieldEmpty;
// Re-export tracing types needed by the macro
pub use tracing::{Instrument, Level, Span, error, event};
