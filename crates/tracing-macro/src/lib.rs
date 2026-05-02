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
/// records returned errors on the current span.
///
/// Supported arguments:
///
/// - target, required. The value must be an allowed path such as `rpc` or `store::database`.
/// - name, required. The value must be a static string literal such as `"store::get_block_header"`.
/// - level, required. The value must be one of `trace`, `debug`, `info`, `warn`, or `error`.
/// - `user`, optional. Marks the span for user-facing logs and registers it in the user-facing
///   metadata catalog.
/// - `err`, optional. Forces returned-error recording for return types that are aliases around
///   `Result`, such as `type StoreResult<T> = Result<T, StoreError>`.
///
/// Returned errors are recorded automatically when the return type is written directly as
/// `Result<_, _>`. Rust procedural macros cannot resolve type aliases, so aliased result types
/// must use the explicit `err` marker.
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
/// #[instrument(store::database, "store::get_block_header", debug, err)]
/// async fn get_block_header(
///     block_num: miden_protocol::block::BlockNumber,
/// ) -> StoreResult<()> {
///     Span::current().record_field(&block_num);
///
///     // Returning `Err` records the error on the current span.
///     Ok(())
/// }
/// ```
///
/// ```ignore
/// #[miden_node_tracing::instrument(rpc, "rpc::get_block", info)]
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
/// event!(<allowed target>, <message literal>, <level>, [user,] justification = "<why event>")
/// ```
///
/// Add `user` after the required level to mark the event for user-facing logs and register its
/// static message template in the user-facing metadata catalog. `justification` is required but is
/// only inspected at compile time; it should explain why this is an event instead of a span. The
/// macro returns an [`Event`] handle; record typed fields or objects on that handle and call
/// `emit()`, or let it emit when dropped.
///
/// # Examples
///
/// ```ignore
/// use miden_node_tracing::event;
///
/// let event = event!(
///     sequencer::block_builder,
///     "built block",
///     info,
///     user,
///     justification = "records a user-visible milestone after the build span closes",
/// );
/// event.record_field(&block_num);
/// event.record_object_as(&header, "block");
/// event.emit();
/// ```
///
/// ```ignore
/// let event = miden_node_tracing::event!(
///     rpc,
///     "request used an old block number",
///     warn,
///     user,
///     justification = "the request is rejected before there is useful span work to time",
/// );
/// event.record_field_as(&block_num, "request.block_number");
/// event.emit();
/// ```
///
/// [`Event`]: https://docs.rs/miden-node-tracing/latest/miden_node_tracing/struct.Event.html
#[proc_macro]
pub fn event(input: TokenStream) -> TokenStream {
    event::event(input)
}

/// Records a trace-level event on the current Miden span.
///
/// This uses the fixed `trace` level and does not accept a level argument. Add `user` after the
/// required message to mark the event for user-facing logs and register its static message template
/// in the user-facing metadata catalog. `justification` is required and compile-time only.
///
/// # Examples
///
/// ```ignore
/// let event = miden_node_tracing::trace!(
///     sequencer::mempool,
///     "selected transaction from mempool",
///     user,
///     justification = "records a sampled selection without adding another nested span",
/// );
/// event.record_field(&transaction_id);
/// event.emit();
/// ```
///
/// [`event!`]: macro@event
#[proc_macro]
pub fn trace(input: TokenStream) -> TokenStream {
    event::trace(input)
}

/// Records a debug-level event on the current Miden span.
///
/// This uses the fixed `debug` level and does not accept a level argument. Add `user` after the
/// required message to mark the event for user-facing logs and register its static message template
/// in the user-facing metadata catalog. `justification` is required and compile-time only.
///
/// # Examples
///
/// ```ignore
/// let event = miden_node_tracing::debug!(
///     store::database,
///     "loaded block from database",
///     justification = "records a cache miss branch without adding duration data",
/// );
/// event.record_field_as(&block_num, "block.number");
/// event.emit();
/// ```
///
/// [`event!`]: macro@event
#[proc_macro]
pub fn debug(input: TokenStream) -> TokenStream {
    event::debug(input)
}

/// Records an info-level event on the current Miden span.
///
/// This uses the fixed `info` level and does not accept a level argument. Add `user` after the
/// required message to mark the event for user-facing logs and register its static message template
/// in the user-facing metadata catalog. `justification` is required and compile-time only.
///
/// # Examples
///
/// ```ignore
/// let event = miden_node_tracing::info!(
///     sequencer::block_builder,
///     "accepted block",
///     user,
///     justification = "records the user-facing acceptance point after validation spans complete",
/// );
/// event.record_field(&block_num);
/// event.record_object(&header);
/// event.emit();
/// ```
///
/// [`event!`]: macro@event
#[proc_macro]
pub fn info(input: TokenStream) -> TokenStream {
    event::info(input)
}

/// Records a warn-level event on the current Miden span.
///
/// This uses the fixed `warn` level and does not accept a level argument. Add `user` after the
/// required message to mark the event for user-facing logs and register its static message template
/// in the user-facing metadata catalog. `justification` is required and compile-time only.
///
/// # Examples
///
/// ```ignore
/// let event = miden_node_tracing::warn!(
///     rpc,
///     "request referenced an account that is not cached",
///     justification = "records an input-dependent rejection before starting downstream work",
/// );
/// event.record_field_as(&account_id, "account.id");
/// event.emit();
/// ```
///
/// [`event!`]: macro@event
#[proc_macro]
pub fn warn(input: TokenStream) -> TokenStream {
    event::warn(input)
}

/// Records an error-level event on the current Miden span.
///
/// This uses the fixed `error` level and does not accept a level argument. Add `user` after the
/// required message to mark the event for user-facing logs and register its static message template
/// in the user-facing metadata catalog. `justification` is required and compile-time only.
///
/// This macro does not record an error status by itself. Prefer [`instrument`] for fallible
/// operations so returned errors are recorded automatically.
///
/// # Examples
///
/// ```ignore
/// let event = miden_node_tracing::error!(
///     ntxb::database,
///     "failed to persist batch metadata",
///     justification = "records a terminal failure after the fallible span records status",
/// );
/// event.record_field(&batch_id);
/// event.emit();
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
/// the second argument. The level is built into this macro and is not accepted as an argument.
/// Fields are not accepted in the macro invocation; record fields or objects on the returned
/// `miden_node_tracing::Span` instead. Add `user` after the name to mark the span for user-facing
/// logs and register it in the user-facing metadata catalog.
///
/// # Examples
///
/// ```ignore
/// let span = miden_node_tracing::trace_span!(
///     sequencer::mempool,
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
/// the second argument. The level is built into this macro and is not accepted as an argument.
/// Fields are not accepted in the macro invocation; record fields or objects on the returned
/// `miden_node_tracing::Span` instead. Add `user` after the name to mark the span for user-facing
/// logs and register it in the user-facing metadata catalog.
///
/// # Examples
///
/// ```ignore
/// let span = miden_node_tracing::debug_span!(
///     store::database,
///     "store::read_block",
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
/// the second argument. The level is built into this macro and is not accepted as an argument.
/// Fields are not accepted in the macro invocation; record fields or objects on the returned
/// `miden_node_tracing::Span` instead. Add `user` after the name to mark the span for user-facing
/// logs and register it in the user-facing metadata catalog.
///
/// # Examples
///
/// ```ignore
/// let span = miden_node_tracing::info_span!(
///     sequencer::block_builder,
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
/// the second argument. The level is built into this macro and is not accepted as an argument.
/// Fields are not accepted in the macro invocation; record fields or objects on the returned
/// `miden_node_tracing::Span` instead. Add `user` after the name to mark the span for user-facing
/// logs and register it in the user-facing metadata catalog.
///
/// # Examples
///
/// ```ignore
/// let span = miden_node_tracing::warn_span!(
///     rpc,
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
/// the second argument. The level is built into this macro and is not accepted as an argument.
/// Fields are not accepted in the macro invocation; record fields or objects on the returned
/// `miden_node_tracing::Span` instead. Add `user` after the name to mark the span for user-facing
/// logs and register it in the user-facing metadata catalog.
///
/// # Examples
///
/// ```ignore
/// let span = miden_node_tracing::error_span!(
///     ntxb::database,
///     "ntxb::database::write_batch",
/// );
/// span.record_field(&batch_id);
/// let _guard = span.entered();
/// ```
#[proc_macro]
pub fn error_span(input: TokenStream) -> TokenStream {
    span::error_span(input)
}
