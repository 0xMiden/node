use proc_macro::TokenStream;

mod event;
mod instrument;
mod level;
mod metadata;
mod name;
mod span;
mod target;
mod user;

/// Instruments a function with Miden tracing defaults.
///
/// This is a restricted wrapper around [`tracing::instrument`]. It always applies `skip_all`,
/// requires a target from the Miden target allowlist, rejects `fields`, `skip`, `skip_all`, and
/// `err`, and records returned errors on the current span.
///
/// Supported arguments:
///
/// - `target = ...`, required. The value must be an allowed path such as `rpc` or
///   `store::database`.
/// - `name = ...`, optional. The value must be a static string literal such as
///   `"store::get_block_header"`. Defaults to the function name.
/// - `level = ...`, optional. The value must be one of `trace`, `debug`, `info`, `warn`, or
///   `error`. Defaults to `info`.
/// - `user`, optional. Marks the span for user-facing logs and registers it in the user-facing
///   metadata catalog.
///
/// The function's doc comments are also registered as the span metadata description. Function
/// arguments are never recorded automatically; record typed fields or objects explicitly inside the
/// function body.
///
/// # Examples
///
/// ```ignore
/// use miden_node_tracing::{Span, instrument};
///
/// /// Loads a block header from the store database.
/// #[instrument(target = store::database, name = "store::get_block_header", level = debug)]
/// async fn get_block_header(
///     block_num: miden_protocol::block::BlockNumber,
/// ) -> Result<(), anyhow::Error> {
///     Span::current().record_field(&block_num);
///
///     // Returning `Err` records the error on the current span.
///     Ok(())
/// }
/// ```
///
/// ```ignore
/// #[miden_node_tracing::instrument(target = rpc)]
/// fn get_block() -> Result<(), anyhow::Error> {
///     Ok(())
/// }
/// ```
///
/// [`tracing::instrument`]: https://docs.rs/tracing/latest/tracing/attr.instrument.html
#[proc_macro_attribute]
pub fn instrument(attr: TokenStream, item: TokenStream) -> TokenStream {
    instrument::instrument(attr, item)
}

/// Records an event on the current Miden span with an explicit level.
///
/// The event respects the configured Miden target and level filters. Disabled targets and levels
/// avoid constructing the event attributes.
///
/// Syntax:
///
/// ```text
/// event!(target = <allowed target>, level = <level>, [user,] [records...], <message literal>, [format args...])
/// ```
///
/// `target` must be first and `level` must follow it. Records, when present, must appear before the
/// required message. `field(value)` records an [`OpenTelemetryField`] with its default key, and
/// `object(value)` records an [`OpenTelemetryObject`] with its default prefix. Use
/// `field(custom.key = value)` or `object(custom.prefix = value)` to override that key or prefix.
/// Add `user` before any records to mark the event for user-facing logs and register its static
/// message template in the user-facing metadata catalog.
///
/// # Examples
///
/// ```ignore
/// use miden_node_tracing::event;
///
/// event!(
///     target = sequencer::block_builder,
///     level = info,
///     user,
///     field(block_num),
///     object(block = header),
///     "built block {}",
///     block_num.as_u32(),
/// );
/// ```
///
/// ```ignore
/// miden_node_tracing::event!(
///     target = rpc,
///     level = warn,
///     user,
///     field(request.block_number = block_num),
///     "request used an old block number",
/// );
/// ```
///
/// [`OpenTelemetryField`]: https://docs.rs/miden-node-tracing/latest/miden_node_tracing/trait.OpenTelemetryField.html
/// [`OpenTelemetryObject`]: https://docs.rs/miden-node-tracing/latest/miden_node_tracing/trait.OpenTelemetryObject.html
#[proc_macro]
pub fn event(input: TokenStream) -> TokenStream {
    event::event(input)
}

/// Records a trace-level event on the current Miden span.
///
/// This is shorthand for [`event!`] with `level = trace`. `target` is required and must be first.
/// Typed `field(...)` and `object(...)` records may be supplied before the required message.
/// Add `user` before any records to mark the event for user-facing logs and register its static
/// message template in the user-facing metadata catalog.
///
/// # Examples
///
/// ```ignore
/// miden_node_tracing::trace!(
///     target = sequencer::mempool,
///     user,
///     field(transaction_id),
///     "selected transaction from mempool",
/// );
/// ```
///
/// [`event!`]: macro@event
#[proc_macro]
pub fn trace(input: TokenStream) -> TokenStream {
    event::trace(input)
}

/// Records a debug-level event on the current Miden span.
///
/// This is shorthand for [`event!`] with `level = debug`. `target` is required and must be first.
/// Typed `field(...)` and `object(...)` records may be supplied before the required message.
/// Add `user` before any records to mark the event for user-facing logs and register its static
/// message template in the user-facing metadata catalog.
///
/// # Examples
///
/// ```ignore
/// miden_node_tracing::debug!(
///     target = store::database,
///     field(block.number = block_num),
///     "loaded block from database",
/// );
/// ```
///
/// [`event!`]: macro@event
#[proc_macro]
pub fn debug(input: TokenStream) -> TokenStream {
    event::debug(input)
}

/// Records an info-level event on the current Miden span.
///
/// This is shorthand for [`event!`] with `level = info`. `target` is required and must be first.
/// Typed `field(...)` and `object(...)` records may be supplied before the required message.
/// Add `user` before any records to mark the event for user-facing logs and register its static
/// message template in the user-facing metadata catalog.
///
/// # Examples
///
/// ```ignore
/// miden_node_tracing::info!(
///     target = sequencer::block_builder,
///     user,
///     field(block_num),
///     object(header),
///     "accepted block",
/// );
/// ```
///
/// [`event!`]: macro@event
#[proc_macro]
pub fn info(input: TokenStream) -> TokenStream {
    event::info(input)
}

/// Records a warn-level event on the current Miden span.
///
/// This is shorthand for [`event!`] with `level = warn`. `target` is required and must be first.
/// Typed `field(...)` and `object(...)` records may be supplied before the required message.
/// Add `user` before any records to mark the event for user-facing logs and register its static
/// message template in the user-facing metadata catalog.
///
/// # Examples
///
/// ```ignore
/// miden_node_tracing::warn!(
///     target = rpc,
///     field(account.id = account_id),
///     "request referenced an account that is not cached",
/// );
/// ```
///
/// [`event!`]: macro@event
#[proc_macro]
pub fn warn(input: TokenStream) -> TokenStream {
    event::warn(input)
}

/// Records an error-level event on the current Miden span.
///
/// This is shorthand for [`event!`] with `level = error`. `target` is required and must be first.
/// Typed `field(...)` and `object(...)` records may be supplied before the required message.
/// Add `user` before any records to mark the event for user-facing logs and register its static
/// message template in the user-facing metadata catalog.
///
/// This macro does not record an error status by itself. Prefer [`instrument`] for fallible
/// operations so returned errors are recorded automatically.
///
/// # Examples
///
/// ```ignore
/// miden_node_tracing::error!(
///     target = ntxb::database,
///     field(batch_id),
///     "failed to persist batch metadata",
/// );
/// ```
///
/// [`event!`]: macro@event
/// [`instrument`]: macro@instrument
#[proc_macro]
pub fn error(input: TokenStream) -> TokenStream {
    event::error(input)
}

/// Creates a trace-level Miden span.
///
/// The macro requires an allowed `target` as the first argument and a span-name string literal as
/// the second argument. Fields are not accepted in the macro invocation; record fields or objects
/// on the returned `miden_node_tracing::Span` instead. Add `user` after the name to mark the span
/// for user-facing logs and register it in the user-facing metadata catalog.
///
/// # Examples
///
/// ```ignore
/// let span = miden_node_tracing::trace_span!(
///     target = sequencer::mempool,
///     "mempool::select_transaction",
/// );
/// span.record_field(&transaction_id);
/// let _guard = span.entered();
/// ```
#[proc_macro]
pub fn trace_span(input: TokenStream) -> TokenStream {
    span::trace_span(input)
}

/// Creates a debug-level Miden span.
///
/// The macro requires an allowed `target` as the first argument and a span-name string literal as
/// the second argument. Fields are not accepted in the macro invocation; record fields or objects
/// on the returned `miden_node_tracing::Span` instead. Add `user` after the name to mark the span
/// for user-facing logs and register it in the user-facing metadata catalog.
///
/// # Examples
///
/// ```ignore
/// let span = miden_node_tracing::debug_span!(
///     target = store::database,
///     name = "store::read_block",
/// );
/// span.record_field(&block_num);
/// let _guard = span.entered();
/// ```
#[proc_macro]
pub fn debug_span(input: TokenStream) -> TokenStream {
    span::debug_span(input)
}

/// Creates an info-level Miden span.
///
/// The macro requires an allowed `target` as the first argument and a span-name string literal as
/// the second argument. Fields are not accepted in the macro invocation; record fields or objects
/// on the returned `miden_node_tracing::Span` instead. Add `user` after the name to mark the span
/// for user-facing logs and register it in the user-facing metadata catalog.
///
/// # Examples
///
/// ```ignore
/// let span = miden_node_tracing::info_span!(
///     target = sequencer::block_builder,
///     "block_builder::build_block",
///     user,
/// );
/// span.record_object(&header);
/// let _guard = span.entered();
/// ```
#[proc_macro]
pub fn info_span(input: TokenStream) -> TokenStream {
    span::info_span(input)
}

/// Creates a warn-level Miden span.
///
/// The macro requires an allowed `target` as the first argument and a span-name string literal as
/// the second argument. Fields are not accepted in the macro invocation; record fields or objects
/// on the returned `miden_node_tracing::Span` instead. Add `user` after the name to mark the span
/// for user-facing logs and register it in the user-facing metadata catalog.
///
/// # Examples
///
/// ```ignore
/// let span = miden_node_tracing::warn_span!(
///     target = rpc,
///     "rpc::slow_request",
/// );
/// span.record_field(&block_num);
/// let _guard = span.entered();
/// ```
#[proc_macro]
pub fn warn_span(input: TokenStream) -> TokenStream {
    span::warn_span(input)
}

/// Creates an error-level Miden span.
///
/// The macro requires an allowed `target` as the first argument and a span-name string literal as
/// the second argument. Fields are not accepted in the macro invocation; record fields or objects
/// on the returned `miden_node_tracing::Span` instead. Add `user` after the name to mark the span
/// for user-facing logs and register it in the user-facing metadata catalog.
///
/// # Examples
///
/// ```ignore
/// let span = miden_node_tracing::error_span!(
///     target = ntxb::database,
///     "ntxb::database::write_batch",
/// );
/// span.record_field(&batch_id);
/// let _guard = span.entered();
/// ```
#[proc_macro]
pub fn error_span(input: TokenStream) -> TokenStream {
    span::error_span(input)
}
