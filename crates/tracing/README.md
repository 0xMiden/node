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

## Failure classes

An error that implements `Classified` reports a `FailureClass` with a short kind, such as `Rejected("expired")`.
`#[miden_instrument(err)]` records them on the span as `failure.class` and `failure.kind`:

| `failure.class` | Meaning                                                            | Span status      |
| --------------- | ------------------------------------------------------------------ | ---------------- |
| `rejected`      | The request was invalid, or conflicts with the state it refers to. | Unset            |
| `transient`     | A node failure that is expected to resolve itself.                 | Error at `ERROR` |
| `fault`         | A node failure that needs an operator.                             | Error at `ERROR` |

A rejection is the node behaving correctly, so its error event is recorded at `DEBUG`, or at the configured level when
that is more verbose, and never sets the span status to error. For other classes, `err(level = ...)` sets the event
level as described above. Errors that do not implement `Classified` keep the configured level and record no failure
attributes.

`tonic::Status` is classified by its code with `FailureClass::from_grpc_code`.

## License

This project is [MIT licensed](../../LICENSE).
