# Monitoring

Developer level overview of how we aim to use `tracing` and `open-telemetry` to provide monitoring and telemetry for the
node.

Please begin by reading through the [monitoring operator guide](https://0xmiden.github.io/miden-docs/node/operator/monitoring) as this will
provide some much needed context.

## Approach and philosophy

We want to trace important information such that we can quickly recognise issues (monitoring & alerting) and identify
the cause. Conventionally this has been achieved via metrics and logs respectively, however a more modern approach is
using wide-events/traces and post-processing these instead. We're using the OpenTelemetry standard for this, however we
are only using the trace pillar and avoid metrics and logs.

We wish to emit these traces without compromising on code quality and readability. This is also a downside to including
metrics - these are usually emitted inline with the code, causing noise and obscuring the business logic. Ideally we
want to rely almost entirely on `tracing::#[instrument]` to create spans as these live outide the function body.

There are of course exceptions to the rule - usually the root span itself is created manually e.g. a new root span for
each block building iteration. Inner spans should ideally keep to `#[instrument]` where possible.

## Relevant crates

We've attempted to lock most of the OpenTelemetry crates behind our own abstractions in the `utils` crate. There are a
lot of these crates and it can be difficult to keep them all separate when writing new code. We also hope this will
provide a more consistent result as we build out our monitoring.

`tracing` is the defacto standard for logging and tracing within the Rust ecosystem. OpenTelemetry has decided to avoid
fracturing the ecosystem and instead attempts to bridge between `tracing` and the OpenTelemetry standard in-so-far as is
possible. All this to say that there are some rough edges where the two combine - this should improve over time.

| crate                                                                                      | description                                                                                                                                            |
| ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| [`tracing`](https://docs.rs/tracing)                                                       | Emits tracing spans and events.                                                                                                                        |
| [`tracing-subscriber`](https://docs.rs/tracing-subscriber)                                 | Provides the conventional `tracing` stdout logger (no interaction with OpenTelemetry).                                                                 |
| [`tracing-forest`](https://docs.rs/tracing-forest)                                         | Logs span trees to stdout. Useful to visualize span relations, but cannot trace across RPC boundaries as it doesn't understand remote tracing context. |
| [`tracing-opentelemetry`](https://docs.rs/tracing-opentelemetry)                           | Bridges the gaps between `tracing` and the OpenTelemetry standard.                                                                                     |
| [`opentelemetry`](https://docs.rs/opentelemetry)                                           | Defines core types and concepts for OpenTelemetry.                                                                                                     |
| [`opentelemetry-otlp`](https://docs.rs/opentelemetry-otlp)                                 | gRPC exporter for OpenTelemetry traces.                                                                                                                |
| [`opentelemetry_sdk`](https://docs.rs/opentelemetry_sdk)                                   | Provides the OpenTelemetry abstractions for metrics, logs and traces.                                                                                  |
| [`opentelemetry-semantic-conventions`](https://docs.rs/opentelemetry-semantic-conventions) | Constants for naming conventions as per OpenTelemetry standard.                                                                                        |

## Important concepts

### OpenTelemetry standards & documentation

<https://opentelemetry.io/docs>

There is a lot. You don't need all of it - look things up as and when you stumble into confusion.

It is probably worth reading through the naming conventions to get a sense of style.

### Footguns and common issues

`tracing` requires data to be known statically e.g. you cannot add span attributes dynamically. `tracing-opentelemetry`
provides a span extension trait which works around this limitation - however this dynamic information is _only_ visible
to the OpenTelemetry processing i.e. `tracing_subscriber` won't see this at all.

In general, you'll find that `tracing` subscribers are blind to any extensions or OpenTelemetry specific concepts. The
reverse is of course not true because OpenTelemetry is integrating with `tracing`.

Another pain point is error stacks - or rather lack thereof. `#[tracing::instrument(err)]` correctly marks the span as
an error, however unfortunately the macro only uses the `Display` or `Debug` implementation of the error. This means you
are missing the error reports entirely. `tracing_opentelemetry` reuses the stringified error data provided by `tracing`
so currently there is no work-around for this. Using `Debug` via `?err` at least shows some information but one still
misses the actual error messages which is quite bad.

Manually instrumenting code (i.e. without `#[instrument]`) can be rather error prone because async calls must be
manually instrumented each time. And non-async code also requires holding the span.

### Distributed context

We track traces across our components by injecting the parent span ID into the gRPC client's request metadata. The
server side then extracts this and uses this as the parent span ID for its processing.

<div class="warning">

This is an OpenTelemetry concept - conventional `tracing` cannot follow these relations.

</div>

Read more in the official OpenTelemetry [documentation](https://opentelemetry.io/docs/concepts/context-propagation/).

### Choosing spans

A root span should represent a set of operations that belong together. It also shouldn't live forever as span
information is usually only sent once the span _closes_ i.e. a root span around the entire node makes no sense as the
operation runs forever.

A good convention to follow is creating child spans for timing information you may want when debugging a failure or slow
operation. As an example, it may make sense to instrument a mutex locking function to visualize the contention on it. Or
separating the database file IO from the sqlite statement creation. Essentially operations which you would otherwise
consider logging the timings for should be separate spans. While you may find this changes the code you might otherwise
create, we've found this actually results in fairly good structure since it follows your business logic sense.

### Inclusions and naming conventions

Where possible, attempt to find and use the naming conventions specified by the standard, ideally via the
`opentelemetry-semantic-conventions` crate.

Include information you'd want to see when debugging - make life easy for your future self looking at data at 3AM on a
Saturday. Also consider what information may be useful when correlating data e.g. client IP.
