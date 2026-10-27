# Miden node tracing

This crate defines the Miden node's tracing attributes and macros, and configures its OpenTelemetry and stdout tracing
layers.

It is part of the [Miden node](https://github.com/0xMiden/node#readme) repository.

## Error events

`#[miden_instrument(err)]` emits one typed error event when the function returns `Err`. `error!(error, "event.name")`
records an explicit typed error event. The optional error argument to `trace!`, `debug!`, `info!`, and `warn!` uses the
same representation.

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
`rpc.grpc.status_code`. It logs each failed request once, with its status code and message. `INTERNAL`, `DATA_LOSS` and
`UNAVAILABLE` are logged at `ERROR`, which sets the span status to error. Other codes describe the request, so they are
logged at `INFO`.

A function that handles requests does not need `#[miden_instrument(err)]`, because the trace layer already logs the
failure at the level its status code calls for. Log an internal error with its causes where it is converted to a status
instead, since the status message should not expose node internals to clients.

## License

This project is [MIT licensed](../../LICENSE).
