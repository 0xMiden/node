# Miden node tracing

This crate defines the Miden node's tracing attributes and macros, and configures its OpenTelemetry and stdout tracing
layers.

It is part of the [Miden node](https://github.com/0xMiden/node#readme) repository.

## Administration API

Merge `miden_node_tracing::admin::router()` into a private administration router after calling `setup_tracing`. It
provides independent stdout and OpenTelemetry filter updates and declared target listing. The caller must provide
external authentication and network isolation. See [Logging](../../docs/external/src/logging.md) for the HTTP contract
and operating procedure.

## Scoped targets

Use `declare_targets!` once at the crate root, before child module declarations, to give `#[instrument_v2]`, v2 events,
and enabled checks a shared diagnostic target without repeating it at each call site:

```rust
miden_node_tracing::declare_targets! {
    default: "miden::storage",
    "miden_node_store::db" => "miden::storage::sqlite",
    "miden_node_store::accounts" => "miden::storage::rocksdb",
    "miden_node_store::blocks" => "miden::storage::files",
}

mod accounts;
mod blocks;
mod db;
```

The most specific matching module prefix wins, regardless of rule order. Rules match complete module names and their
descendants: `miden_node_store::db` includes `db::queries`, but not `db_backup`. Modules outside the configured subtrees
use the default target. Resolution happens at compile time; generic functions use the module where they are defined.
Update the map when moving or renaming a configured module.

The declaration generates an inventory of compiled call sites in test builds and a test requiring every mapping rule to
win for at least one call site. Registration uses the inventory re-exported by this crate, so callers need no extra
dependency. This detects stale and shadowed rules without executing the instrumented code. The check covers the features
compiled into the test binary.

`miden_node_tracing::declared_targets()` returns the default and override targets declared by linked crates, sorted and
deduplicated. This list is available at startup without executing instrumented code or enabling tracing output. It
includes only declarations enabled for the build; explicit call site overrides, legacy instrumentation, and dependency
targets are not included unless they also appear in a declaration.

Use `#[instrument_v2(target = "miden::rpc::server")]` to override the scoped target for one function. An explicit target
also works without a scope; otherwise a missing scope is a compile error. The attribute preserves `miden_instrument`'s
canonical fields, inferred fields from `miden_span_record!`, and typed error reporting. Function arguments are always
skipped.

The scoped target applies to the function's span, its automatic `err` event, and calls to `trace_v2!`, `debug_v2!`,
`info_v2!`, `warn_v2!`, and `error_v2!`. These event macros accept the same arguments as their original counterparts,
including typed errors, canonical fields, and an optional `parent:`. An explicit `target:` overrides the scope and works
without one; otherwise a missing scope is a compile error.

```rust
miden_node_tracing::info_v2!("account.loaded", block.number = 42_u32);
miden_node_tracing::warn_v2!(error, parent: &span, "account.load_failed");
miden_node_tracing::info_v2!(target: "miden::rpc::server", "request.completed");
```

Event targets follow their lexical scope, independently of the current span or an explicit event parent. Overriding a
function's span target with `#[instrument_v2(target = "...")]` does not change the target of explicit events in its
body. Use `trace_span_v2!`, `debug_span_v2!`, `info_span_v2!`, `warn_span_v2!`, and `error_span_v2!` for manual spans
with the same scoped target resolution. These accept upstream tracing span fields and explicit `target:` overrides.

The legacy `miden_instrument`, event macros without the `_v2` suffix, and upstream manual span macros retain their
original target defaults. Use the scoped APIs for new instrumentation.

Use `enabled_v2!(Level::DEBUG)` to check subscriber interest before preparing diagnostic data. The check inherits the
same target as scoped spans and events. It also accepts optional field names, such as
`enabled_v2!(Level::DEBUG, block.number)`, and an explicit `target:` override that works without a scope. Like
`tracing::enabled!`, this is an interest hint: filters that depend on event/span kind, source location, or additional
fields can still treat an individual span or event differently. If an event overrides its target, use that same override
in its enabled check.

If the compiler reports a missing `tracing_target` macro, invoke `declare_targets!` at the crate root before child
modules, or supply an explicit target. For instrumentation, use `#[instrument_v2(target = "miden::storage")]`; for an
event, use `info_v2!(target: "miden::storage", "account.loaded")`.

## Error events

`#[instrument_v2(err)]` emits one typed error event when the function returns `Err`. `error_v2!(error, "event.name")`
records an explicit typed error event. The optional error argument to `trace_v2!`, `debug_v2!`, `info_v2!`, and
`warn_v2!` uses the same representation.

The default OpenTelemetry layer records the outer message as `exception.message` and the source messages as the
`exception.stacktrace` array. The subscriber traverses the source chain. This array contains error messages from
`source()`. The compact stdout formatter prints the outer message in `error` and the causes in `error.sources`.

The optional `tracing-forest` stdout layer records only the outer message. It does not traverse typed error sources.

A span status description is an optional explanation of why the operation failed, such as `database unavailable`. It
applies only to the error status. An empty description is valid. The default OpenTelemetry layer sets the span status to
error for an `ERROR` event. It does not copy a typed error's message into the status description. The message is
available in `exception.message`. An error event below `ERROR` does not set the span status to error.

Use `err(level = "warn")` to change the event level. Error formatters such as `err(Debug)` and `err(Display)` are not
supported. The error must implement `std::error::Error + 'static` or dereference to that trait. This includes
`anyhow::Error` and boxed error trait objects. Errors that only implement `Display` or `Debug`, such as strings, are not
supported. Source messages are available only when the error exposes them through `source()`.

The attribute supports synchronous functions, async functions, and functions that end with an async block or
`Box::pin(async { ... })`. Return value logging with `ret` is not supported.

For returned futures, the macro reads the output type from `Future<Output = T>` or Miden's `FutureMaybeSend<T>`. A
custom opaque future trait can require an explicit result type in the async block.

Callers cannot set `exception.message` or `exception.stacktrace` through the event macros. Pass the error as the first
argument so the subscriber can record both fields.

## gRPC servers

`grpc::grpc_trace_layer()` creates a root span for each request and records the response's gRPC status code as
`rpc.grpc.status_code`. These spans and the layer's failure events use `miden::rpc::server`, regardless of the service
or the caller that instantiated the layer. It logs each failed request once, with its status code and message.
`INTERNAL`, `DATA_LOSS` and `UNAVAILABLE` are logged at `ERROR`, which sets the span status to error. Other codes
describe the request, so they are logged at `INFO`.

A function that handles requests does not need `#[instrument_v2(err)]`, because the trace layer already logs the failure
at the level its status code calls for. Log an internal error with its causes where it is converted to a status instead,
since the status message should not expose node internals to clients.

## License

This project is [MIT licensed](../../LICENSE).
