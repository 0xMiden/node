//! Tracing utilities for Miden node with enhanced error reporting.
//!
//! This crate provides an `#[instrument]` attribute macro that enhances
//! the standard `tracing::instrument` with full error chain reporting.
//!
//! # Usage
//!
//! ```rust,ignore
//! use miden_node_tracing::instrument;
//!
//! #[instrument(target = "my_component", skip_all, err)]
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

pub use miden_node_tracing_macro::{debug, error, info, instrument, trace, warn};
pub use miden_node_utils::ErrorReport;
pub use miden_node_utils::tracing::OpenTelemetrySpanExt;
#[doc(hidden)]
pub use opentelemetry::trace::Status as OtelStatus;
#[doc(hidden)]
pub use tracing::field::Empty as FieldEmpty;
#[doc(hidden)]
pub use tracing::{Instrument, Level, Span, event};
