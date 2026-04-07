//! Tracing utilities for Miden node with enhanced error reporting.
//!
//! This crate provides an `#[instrument]` attribute macro that wraps
//! `tracing::instrument` with a custom syntax enforcing OpenTelemetry field
//! naming and optional full error-chain reporting.
//!
//! # Usage
//!
//! ```rust,ignore
//! use miden_node_tracing::instrument;
//!
//! // COMPONENT is a &str const defined in the calling crate.
//! #[instrument(COMPONENT: report)]
//! async fn apply_block(&self, block: Block) -> Result<(), ApplyBlockError> {
//!     // ...
//! }
//! ```
//!
//! All function arguments are skipped automatically. Additional span fields
//! must use names from the OpenTelemetry allowlist:
//!
//! ```rust,ignore
//! #[instrument(COMPONENT: level: DEBUG, account.id = %id, err)]
//! fn get_account(&self, id: AccountId) -> Result<Account, Error> { ... }
//! ```
//!
//! When `report` is used and an error occurs, the full error chain is recorded:
//! ```text
//! ERROR apply_block: error = "failed to apply block
//! caused by: database error
//! caused by: SQLite error: table 'blocks' has 10 columns but 9 values were supplied"
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
