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

Every failed span records a `FailureClass` as `failure.class`, with a short kind such as `expired` as `failure.kind`:

| `failure.class` | Meaning                                                            | Span status |
| --------------- | ------------------------------------------------------------------ | ----------- |
| `rejected`      | The request was invalid, or conflicts with the state it refers to. | Unset       |
| `transient`     | A node failure that is expected to resolve itself.                 | Error       |
| `fault`         | A node failure that needs an operator.                             | Error       |

A span marked as failed always records `transient` or `fault`, so alerts on node failures can use either the span status
or `failure.class`. A span records at most one failure: the first one recorded wins, which is also the one that set the
span status.

An error that implements `Classified` reports its own class. Errors that do not are faults of kind `unclassified`.
`#[derive(Classified)]` implements it for an error enum, with each variant's name in snake case as the kind:

```rust
#[derive(Debug, thiserror::Error, Classified)]
enum BuildBlockError {
    // A fault of kind `store_apply_block_failed`.
    #[error("failed to apply block to store")]
    StoreApplyBlockFailed(#[source] StoreError),
    // Classified by the validator error it wraps.
    #[error("failed to validate block")]
    #[failure(transparent)]
    ValidateBlockFailed(#[source] ValidatorError),
}
```

Variants are faults unless a `#[failure(...)]` attribute on the enum or the variant says `transient` or `rejected`. A
variant with one field can instead be classified by it: `transparent` uses the field's class, `dependency` applies
`FailureClass::from_dependency` to it, and `with = path` calls a function on it, named `classify_*` by convention.

`tonic::Status` is classified by its code with `FailureClass::from_grpc_code`. Error enums that derive `GrpcError` are
classified by the gRPC status code of each variant, with the variant's name as the kind. An error from a component the
node calls is classified with `FailureClass::from_dependency`, which treats a rejection as a fault, since the node sent
the rejected request.

Failures are recorded by:

- `#[miden_instrument(err)]`. A rejection is recorded, and its error event is logged at `INFO`, or at the configured
  level when that is more verbose, so it never sets the span status to error. Other failures are recorded when their
  event is logged at `ERROR`, which marks the span as failed; `err(level = ...)` below `ERROR` records nothing.
- The `error!` macro, which marks its span as failed and records the error's class, or a fault for a rejection.
- `ErrorSpanExt::set_error`, which records an unclassified fault, and `ErrorSpanExt::set_failure`, which records a given
  class and marks the span as failed unless it is a rejection.
- The panic hooks, which record a fault of kind `panic`.

The gRPC servers trace requests with `grpc_trace_layer`, or `public_grpc_trace_layer` for servers exposed to the public.
Each request's root span records the response's status code as `rpc.grpc.status_code`, `0` on success, and a failed
request's class and kind from that code. A public server also treats `UNKNOWN` and `UNIMPLEMENTED` as rejections, since
scanners probing for paths and methods that do not exist receive them.

## License

This project is [MIT licensed](../../LICENSE).
