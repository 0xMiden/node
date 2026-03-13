//! Procedural macros for structured, OTel-aware tracing in the Miden node.
//!
//! **Do not use this crate directly.** Import from `miden-node-tracing` instead, which
//! re-exports every macro here together with all required runtime dependencies
//! (`ErrorReport`, `OpenTelemetrySpanExt`, …).
//!
//! # Overview
//!
//! This crate provides two families of macros that mirror their counterparts in the
//! [`tracing`](https://docs.rs/tracing) crate but extend them with node-specific
//! conventions:
//!
//! | Macro | Purpose |
//! |---|---|
//! | [`#[instrument]`](macro@instrument) | Attribute macro – wraps a function in a tracing span |
//! | [`error!`], [`warn!`], [`info!`], [`debug!`], [`trace!`] | Function-like macros – emit a tracing event |
//!
//! ## Key differences from `tracing`
//!
//! 1. **Component target** – instead of `target = "some::module"` you write a short component name
//!    once (`rpc:`, `store:`, …) and it becomes the span target.
//! 2. **`report` keyword** – a richer alternative to `tracing`'s `err` that walks the full
//!    [`ErrorReport`] chain, emits a structured `error!` event *and* sets the OpenTelemetry span
//!    status to `Error`.
//! 3. **OTel field allowlist** – only names declared in `allowlist.txt` may appear as field keys,
//!    preventing accidental cardinality explosions in the metrics / trace backend.
//! 4. **Log macros** – `warn!`, `error!`, etc. mirror `tracing::<level>!` syntax but additionally
//!    enforce the same `COMPONENT:` target shorthand and OTel field allowlist as `#[instrument]`.
//!
//! # `#[instrument]` – complete reference
//!
//! ## Syntax
//!
//! ```text
//! #[instrument]
//! #[instrument( [COMPONENT:] [element, …] )]
//!
//! COMPONENT  ::= ident | "string literal"
//! element    ::= field-entry | "ret" | "err" | "report"
//! field-entry::= dotted-name "=" ["%"] expr
//! dotted-name::= ident ["." ident]*          -- must be in allowlist.txt
//! ```
//!
//! ## Combinatorial argument table
//!
//! Each row is a distinct, valid (✓) or invalid (✗) combination with the reason.
//!
//! | Attribute arguments | fn return type | Valid? | Notes |
//! |---|---|---|---|
//! | *(empty)* | any | ✓ | Thin wrapper around `#[tracing::instrument]` |
//! | `rpc:` *(no elements)* | any | ✓ | Sets `target = "rpc"`, no field/ret tracking |
//! | `rpc: ret` | any | ✓ | Records return value via `tracing::instrument`'s `ret` |
//! | `rpc: err` | `Result<_, E>` | ✓ | Delegates to `tracing::instrument`'s `err` (single-level `Display`/`Debug`) |
//! | `rpc: err` | non-`Result` | ✗ | Compile error: `err` requires `Result` return |
//! | `rpc: report` | `Result<_, E>` | ✓ | Walks full error chain via [`ErrorReport`], emits `error!` event, sets OTel span status |
//! | `rpc: report` | non-`Result` | ✗ | Compile error: `report` requires `Result` return |
//! | `rpc: err, report` | any | ✗ | Compile error: mutually exclusive |
//! | `rpc: report, err` | any | ✗ | Compile error: mutually exclusive (order does not matter) |
//! | `rpc: ret, err` | `Result<_, E>` | ✓ | Records both return value and error via `tracing::instrument` |
//! | `rpc: ret, report` | `Result<T, E>` | ✓ | Records return value (`ret`) + full error chain (`report`) |
//! | `rpc: ret, report` | non-`Result` | ✗ | Compile error: `report` requires `Result` return |
//! | `rpc: account.id = id` | any | ✓ | Attaches `account.id` field (Debug format, allowlisted) |
//! | `rpc: account.id = %id` | any | ✓ | Attaches `account.id` field (Display format via `%`) |
//! | `rpc: foo = id` | any | ✗ | Compile error: `foo` not in OTel allowlist |
//! | `rpc: foo.bar.baz = %id` | any | ✗ | Compile error: `foo.bar.baz` not in OTel allowlist |
//! | `rpc: account.id = %id, err` | `Result<_, E>` | ✓ | Allowlisted field + standard error tracking |
//! | `rpc: account.id = %id, report` | `Result<_, E>` | ✓ | Allowlisted field + full error chain |
//! | `rpc: account.id = %id, ret, report` | `Result<T, E>` | ✓ | Field + return value + full error chain |
//! | `rpc: account.id = %id, report, err` | `Result<_, E>` | ✗ | Compile error: `report` and `err` are mutually exclusive |
//!
//! ## `err` vs `report`
//!
//! Both keywords require the function to return `Result`.  They differ in *how much* of
//! the error is captured:
//!
//! | | `err` | `report` |
//! |---|---|---|
//! | Mechanism | delegates to `tracing::instrument`'s built-in `err` | custom body wrapper |
//! | Error formatting | top-level `Display` or `Debug` only | full chain via [`ErrorReport::as_report`] (every `source()` cause) |
//! | OTel span status | not set | set to `Error` with the full report string |
//! | tracing event level | `ERROR` (tracing default) | `ERROR` |
//!
//! Use `err` for lightweight internal helpers where the single-level message is
//! sufficient.  Use `report` on RPC handlers, block application paths, and any boundary
//! where the full error chain must appear in the telemetry.
//!
//! ## Field values and the `%` modifier
//!
//! A field entry `name = expr` records `expr` using its `Debug` implementation.
//! Prefixing the value with `%` switches to `Display`:
//!
//! ```rust,ignore
//! #[instrument(rpc: account.id = account_id)]    // Debug  → {:?}
//! #[instrument(rpc: account.id = %account_id)]   // Display → {}
//! ```
//!
//! All field names must appear in `allowlist.txt`.  An attempt to use an unlisted name
//! produces a compile error with fuzzy-matched suggestions.
//!
//! ## Component name
//!
//! The component prefix sets `target` in the underlying `tracing::instrument` span.
//! It can be an identifier or a string literal:
//!
//! ```rust,ignore
//! #[instrument(rpc: ret)]              // target = "rpc"
//! #[instrument("my-rpc": ret)]         // target = "my-rpc"
//! ```
//!
//! When omitted, no `target` override is emitted and tracing uses the default
//! (module path).
//!
//! ## Code generation summary
//!
//! | Combination | Generated code shape |
//! |---|---|
//! | empty attrs | `#[::tracing::instrument] fn …` |
//! | component only / fields / `ret` / `err` | `#[::tracing::instrument(target=…, skip_all?, fields(…)?, ret?, err?)] fn …` |
//! | `report` | `#[::tracing::instrument(…)] fn … { let __result = { … }; if Err(e) { error!(…); set_error(…); } __result }` |
//!
//! # Log macros – complete reference
//!
//! `error!`, `warn!`, `info!`, `debug!`, `trace!` enforce the same `COMPONENT:`
//! target shorthand and OTel field allowlist as `#[instrument]`, then expand to
//! the underlying `tracing::<level>!` macro.
//!
//! ## Syntax
//!
//! ```text
//! warn!( [COMPONENT:] [field = ["%" | "?"] expr ,]* [format_str [, args…]] )
//!
//! COMPONENT   ::= ident | string-literal
//! field-entry ::= dotted-name "=" ["%" | "?"] expr
//! dotted-name ::= ident ["." ident]*   -- must appear in allowlist.txt
//! ```
//!
//! ## Combinatorial argument table for `warn!`
//!
//! | Call form | Example | Valid? | Notes |
//! |---|---|---|---|
//! | message only | `warn!("something odd")` | ✓ | Plain string literal, no component or fields |
//! | format string | `warn!("retrying after {}ms", delay)` | ✓ | `format_args!`-style |
//! | component + message | `warn!(rpc: "something odd")` | ✓ | Emits `target: "rpc"` |
//! | component + format | `warn!(store: "migrated {} rows", n)` | ✓ | |
//! | allowlisted field, Debug | `warn!(account.id = id, "context")` | ✓ | `{:?}` format |
//! | allowlisted field, Display | `warn!(account.id = %id, "context")` | ✓ | `{}` format via `%` |
//! | allowlisted field, Debug explicit | `warn!(account.id = ?id, "context")` | ✓ | `{:?}` format via `?` |
//! | unlisted field | `warn!(foo = %x, "context")` | ✗ | Compile error: `foo` not in allowlist |
//! | unlisted dotted field | `warn!(foo.bar = %x, "context")` | ✗ | Compile error: `foo.bar` not in allowlist |
//! | multiple allowlisted fields | `warn!(account.id = %id, block.number = n, "msg")` | ✓ | Any number of allowlisted fields |
//! | fields only, no message | `warn!(account.id = %id, block.number = n)` | ✓ | Structured event, no message string |
//! | component + fields + message | `warn!(rpc: account.id = %id, "rejected")` | ✓ | Full form |
//! | component + unlisted field | `warn!(rpc: foo = %x, "msg")` | ✗ | Compile error: allowlist applies regardless of component |

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;

mod allowed;
mod instrument;
mod log;

#[cfg(test)]
mod tests;

/// Instruments a function with a [`tracing`] span, with node-specific extensions.
///
/// # Syntax
///
/// ```text
/// #[instrument]
/// #[instrument( [COMPONENT:] [element, …] )]
///
/// COMPONENT   ::= ident | "string literal"
/// element     ::= field-entry | "ret" | "err" | "report"
/// field-entry ::= dotted-name "=" ["%"] expr
/// dotted-name ::= ident ["." ident]*   -- must appear in allowlist.txt
/// ```
///
/// # Component
///
/// An optional `IDENT:` or `"literal":` prefix sets the span's `target`:
///
/// ```rust,ignore
/// #[instrument(rpc: report)]
/// #[instrument("block-producer": err)]
/// ```
///
/// # Keywords
///
/// - **`ret`** – records the return value inside the span (any return type).
/// - **`err`** – on `Err`, emits a tracing event with the top-level error message. Delegates to
///   `tracing::instrument`'s built-in `err`.  Requires `Result` return.
/// - **`report`** – on `Err`, emits an `error!` event containing the *full error chain* via
///   [`miden_node_utils::ErrorReport`] and sets the OpenTelemetry span status to `Error`.  Requires
///   `Result` return.  Mutually exclusive with `err`.
///
/// # Field entries
///
/// ```rust,ignore
/// #[instrument(rpc: account.id = account_id)]   // Debug
/// #[instrument(rpc: account.id = %account_id)]  // Display
/// ```
///
/// Field names must be declared in `allowlist.txt`.  An undeclared name produces a
/// compile error with fuzzy-matched suggestions from the allowlist.
///
/// # Examples
///
/// ```rust,ignore
/// use miden_node_tracing::instrument;
///
/// // Minimal – span with default target, no field tracking.
/// #[instrument]
/// fn simple() {}
///
/// // Component only – sets target = "rpc", no fields.
/// #[instrument(rpc:)]
/// fn also_simple() {}
///
/// // Track return value on any function.
/// #[instrument(rpc: ret)]
/// fn compute() -> u32 { 42 }
///
/// // Standard error tracking (top-level message only).
/// #[instrument(store: err)]
/// async fn load() -> Result<Data, LoadError> { … }
///
/// // Full error chain + OTel span status.
/// #[instrument(rpc: report)]
/// async fn apply_block(&self, block: Block) -> Result<(), ApplyBlockError> { … }
///
/// // Return value tracking combined with full error chain.
/// #[instrument(rpc: ret, report)]
/// async fn fetch_count() -> Result<u32, FetchError> { … }
///
/// // Attach an allowlisted OTel field (Display format).
/// #[instrument(rpc: account.id = %account_id, report)]
/// async fn get_account(account_id: AccountId) -> Result<Account, RpcError> { … }
///
/// // Multiple fields.
/// #[instrument(store: account.id = %account_id, block.number = block_num, err)]
/// async fn get_account_at(
///     account_id: AccountId,
///     block_num: BlockNumber,
/// ) -> Result<Account, StoreError> { … }
/// ```
#[proc_macro_attribute]
pub fn instrument(attr: TokenStream, item: TokenStream) -> TokenStream {
    match instrument::instrument2(TokenStream2::from(attr), TokenStream2::from(item)) {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

/// Emits a tracing event at the `ERROR` level.
///
/// Accepts the same syntax as [`warn!`]: optional `COMPONENT:` target, then
/// zero or more allowlisted `field = [%|?] expr` pairs, then an optional
/// message string with format arguments.
///
/// # Examples
///
/// ```rust,ignore
/// use miden_node_tracing::error;
///
/// error!("something went wrong");
/// error!(rpc: "request failed");
/// error!(rpc: account.id = %id, "request failed");
/// error!("value was {}", x);
/// ```
#[proc_macro]
pub fn error(ts: TokenStream) -> TokenStream {
    match log::parse("error", ts.into()) {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

/// Emits a tracing event at the `WARN` level.
///
/// # Syntax
///
/// ```text
/// warn!( [COMPONENT:] [field = ["%"|"?"] expr ,]* [format_str [, args…]] )
/// ```
///
/// The optional `COMPONENT:` prefix sets the tracing target (e.g. `rpc:` →
/// `target: "rpc"`).  Field names must appear in `allowlist.txt`; an
/// unlisted name is a compile error with fuzzy-matched suggestions.
///
/// # Examples
///
/// ```rust,ignore
/// use miden_node_tracing::warn;
///
/// // Plain message.
/// warn!("something looks off");
///
/// // Component + message.
/// warn!(store: "migration warning");
///
/// // Format string.
/// warn!("retrying after {}ms", delay_ms);
///
/// // Allowlisted field, Display.
/// warn!(account.id = %id, "unexpected account");
///
/// // Allowlisted field, Debug.
/// warn!(account.id = ?id, "unexpected account");
///
/// // Multiple allowlisted fields + message.
/// warn!(account.id = %id, block.number = n, "state inconsistency");
///
/// // Fields only, no message.
/// warn!(account.id = %id, block.number = n);
///
/// // Component + allowlisted field + message (full form).
/// warn!(rpc: account.id = %id, "request rejected");
/// ```
#[proc_macro]
pub fn warn(ts: TokenStream) -> TokenStream {
    match log::parse("warn", ts.into()) {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

/// Emits a tracing event at the `INFO` level.
///
/// Same syntax as [`warn!`]: optional `COMPONENT:`, allowlisted fields, optional message.
///
/// # Examples
///
/// ```rust,ignore
/// use miden_node_tracing::info;
///
/// info!("server started");
/// info!(store: sqlite = %path.display(), "connected to database");
/// info!(account.id = %id, block.number = n, "transaction accepted");
/// info!("processed {} transactions", count);
/// ```
#[proc_macro]
pub fn info(ts: TokenStream) -> TokenStream {
    match log::parse("info", ts.into()) {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

/// Emits a tracing event at the `DEBUG` level.
///
/// Same syntax as [`warn!`]: optional `COMPONENT:`, allowlisted fields, optional message.
///
/// # Examples
///
/// ```rust,ignore
/// use miden_node_tracing::debug;
///
/// debug!("entering handler");
/// debug!(store: "query returned {} rows", n);
/// debug!(block.number = n, "processing block");
/// debug!("batch size: {}", batch.len());
/// ```
#[proc_macro]
pub fn debug(ts: TokenStream) -> TokenStream {
    match log::parse("debug", ts.into()) {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

/// Emits a tracing event at the `TRACE` level.
///
/// Same syntax as [`warn!`]: optional `COMPONENT:`, allowlisted fields, optional message.
///
/// # Examples
///
/// ```rust,ignore
/// use miden_node_tracing::trace;
///
/// trace!("tick");
/// trace!(mempool: "snapshot taken");
/// trace!(nullifier.id = %id, "nullifier lookup");
/// ```
#[proc_macro]
pub fn trace(ts: TokenStream) -> TokenStream {
    match log::parse("trace", ts.into()) {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}
