---
title: "Logging"
sidebar_position: 6
---

# Logging

All Miden node services write compact, structured logs to stderr. To capture logs in a file, use `2>node.log`.
Long-running services can also export OpenTelemetry traces. Local logs and exported traces have independent filters.

## Local log filter

The `MIDEN_STDOUT_FILTER` setting and the `/admin/tracing/stdout-filter` endpoint control logs written to stderr. At
startup, the service uses the first non-empty filter in this order:

1. `MIDEN_STDOUT_FILTER`
2. `RUST_LOG`
3. The default levels described under [User-facing targets](#user-facing-targets).

`MIDEN_STDOUT_FILTER` uses the
[`tracing_subscriber` filter syntax](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html).
A filter is a comma-separated list of directives. A target directive sets the verbosity for that target:

```text
target=level
```

The available levels are `off`, `error`, `warn`, `info`, `debug`, and `trace`. Target directives match by prefix.
`miden` is an alias for `miden::`, so `miden=debug` enables node diagnostics without matching dependencies such as
`miden_processor`.

Bare levels select the verbosity for `miden::` targets. Named target directives override bare levels regardless of
directive order. Dependencies default to `warn`, preserving their warning and error events; enable a named dependency
explicitly to collect more detail. This applies to `RUST_LOG`, both Miden-specific environment variables, and
administration API updates. Unlike the usual `RUST_LOG` behavior, a bare `debug` does not enable debug output from
dependencies.

| Input                    | Effective filter                         |
| ------------------------ | ---------------------------------------- |
| `info`                   | `warn,miden::=info`                      |
| `debug` or `miden=debug` | `warn,miden::=debug`                     |
| `info,tonic=debug`       | `warn,miden::=info,tonic=debug`          |
| `info,miden_prover=off`  | `warn,miden::=info,miden_prover=off`     |
| `miden::storage=debug`   | `warn,miden::=info,miden::storage=debug` |
| `off`                    | `off`                                    |

A bare `off` disables all output except explicitly named overrides. For example, `off,tonic=debug` collects only `tonic`
diagnostics. Use `miden=off` to disable node diagnostics while retaining dependency warnings and errors.

For example, keep node and dependency output at `warn`, show user-facing and storage events at `info`, and enable
detailed RPC events:

```bash
MIDEN_STDOUT_FILTER='warn,user=info,miden::storage=info,miden::rpc::server=debug' \
miden-node full ...
```

To temporarily enable debug logs for all node targets:

```bash
MIDEN_STDOUT_FILTER=debug miden-node full ...
```

To configure a container, pass the filter as an environment variable:

```bash
docker run --rm \
  -e MIDEN_STDOUT_FILTER='warn,user=info,miden::storage=info,miden::rpc::server=debug' \
  ghcr.io/0xmiden/miden-node:<release-tag> \
  miden-node full ...
```

For systemd, set the same value in the service unit or an environment file, then restart the service:

```ini
[Service]
Environment="MIDEN_STDOUT_FILTER=warn,user=info,miden::storage=info,miden::rpc::server=debug"
```

`RUST_LOG` is a compatibility fallback. Prefer `MIDEN_STDOUT_FILTER` when configuring stderr independently from
OpenTelemetry.

## User-facing targets

The default stderr filter enables `debug` events for `user::*`, `miden::storage`, `miden::rpc::server`,
`miden::production`, `miden::mempool`, `miden::proving`, `miden::sync`, `miden::validation`, `miden::privacy`,
`miden::admin`, `miden::funding`, `miden::monitor`, and `miden::http::server`. The compact stderr format does not print
the target name, but the filter still matches it.

`info` is intended for production use, such as on the sequencer of a Miden network, where detailed per-call or
per-transaction messages would create undesirable noise. Events whose primary use case is local development therefore
use the `debug` level, even when they are user-visible. Shared RPC client diagnostics and other node targets default to
`info`. Dependencies default to `warn`.

| Target                            | Events                                                            |
| --------------------------------- | ----------------------------------------------------------------- |
| `miden::process`                  | General process startup, configuration, shutdown, and fatal exits |
| `miden::rpc::server`              | RPC requests, subscriptions, readiness, and submissions           |
| `miden::production`               | Sequencer orchestration and fee-collector operations              |
| `miden::production::transactions` | Network transaction scheduling, note selection, and execution     |
| `miden::production::batches`      | Transaction selection and batch assembly                          |
| `miden::production::blocks`       | Batch selection, block assembly, and committing blocks            |
| `miden::mempool`                  | Transaction dependencies, readiness, capacity, and eviction       |
| `miden::proving::transactions`    | Transaction proof requests and results                            |
| `miden::proving::batches`         | Batch execution and proving                                       |
| `miden::proving::blocks`          | Block proof scheduling, retries, and results                      |
| `miden::sync`                     | Chain and account synchronization progress and readiness          |
| `miden::sync::blocks`             | Receiving, validating, and applying committed blocks              |
| `miden::sync::proofs`             | Receiving and applying block proofs                               |
| `miden::rpc::client`              | Outgoing RPC requests and client diagnostics                      |
| `miden::storage`                  | Persistence and account, note, and storage lifecycle events       |
| `miden::validation`               | Transaction and block validation                                  |
| `miden::validation::transactions` | Transaction proof verification and re-execution                   |
| `miden::validation::blocks`       | Block validation and signing                                      |
| `miden::privacy::dkg`             | Storage-key setup ceremonies                                      |
| `miden::admin`                    | Private administration API diagnostics                            |
| `miden::funding`                  | Funding requests, transaction construction, and delivery          |
| `miden::monitor`                  | Network health checks, end-to-end probes, and probe setup         |
| `miden::http::client`             | Outgoing HTTP requests                                            |
| `miden::http::server`             | Funding and dashboard HTTP requests, dashboard listener readiness |
| `miden::cache`                    | In-memory cache lock spans                                        |

Network monitor startup and configuration messages use the `miden::process` target.

Network monitor probes have separate child targets under `miden::monitor`: `rpc`, `prover`, `faucet`, `funding`,
`explorer`, `validator`, `note_transport`, `agglayer`, and `transactions`. The transactions target includes account
setup, fee funding, and wallet recovery for the end-to-end transaction probe. For example, enable detailed prover probe
logs while keeping other monitor diagnostics at `info`:

```text
miden::monitor=info,miden::monitor::prover=debug
```

General process messages use the `miden::process` target. Operational work uses activity targets such as
`miden::storage`, `miden::sync`, and `miden::admin`. Set a baseline with `miden=info` and override individual activities
as needed, for example `miden=info,miden::sync=debug`.

A `miden-node` process contains multiple components. For example, a sequencer can emit `miden::process`,
`miden::rpc::server`, `miden::production`, `miden::mempool`, `miden::proving`, and `miden::storage` events.

## Select a span

For HTTP and gRPC requests, filter by OpenTelemetry span kind to see time spent by the caller (`client`) or the
recipient (`server`). For gRPC calls with context propagation enabled, the server span appears under its client span.

Span names describe operations such as `build_block`; targets identify activities such as `miden::production::blocks`.
Combine both to enable diagnostics within a particular operation:

```text
info,miden::production::blocks[build_block]=debug
```

The target matches by prefix and the span name matches exactly. The directive also enables debug output within that
span's scope, including output from other targets. Use it with `MIDEN_STDOUT_FILTER`, `MIDEN_OTEL_FILTER`, or the
administration API.

## OpenTelemetry filter

OpenTelemetry export is enabled when either `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` or `OTEL_EXPORTER_OTLP_ENDPOINT` has a
non-empty value. Its filter is selected independently from the first non-empty value in this order:

1. `MIDEN_OTEL_FILTER`
2. `RUST_LOG`
3. `info` (default; node targets at `info`, dependencies at `warn`)

For example, retain debug-level user-facing, storage, and RPC events in the tracing backend while keeping stderr
quieter:

```bash
MIDEN_STDOUT_FILTER='warn,user=info,miden::storage=info,miden::rpc::server=info' \
MIDEN_OTEL_FILTER='info,user=debug,miden::storage=debug,miden::rpc::server=debug' \
OTEL_EXPORTER_OTLP_ENDPOINT=http://collector:4317 \
miden-node full ...
```

If neither Miden-specific filter is set, `RUST_LOG` configures both outputs. See
[Monitoring](/network-operator/monitoring) for exporter and resource configuration.

Exported spans include their tracing target in the `target` attribute. Use it alongside `service.name` and the span name
when filtering or grouping operations in the tracing backend. Short span names can occur under multiple targets or
services, so dashboards and derived metrics should retain those dimensions when they need to distinguish the operations.

## Change filters while the service is running

Each service can expose an administration API to replace either tracing filter without restarting. Use this to collect
more detail during an investigation, then restore your usual filter when finished. Updates affect only the process
receiving the request and last until its next restart.

The listener is disabled by default. Add `--admin.listen <IP:PORT>` when starting the service. Use the service's
`--help` output for its startup options. For example:

```bash
miden-node full --admin.listen 127.0.0.1:50100 ...
miden-remote-prover --admin.listen 127.0.0.1:50101 ...
```

You can also configure the address with the `MIDEN_ADMIN_LISTEN` environment variable.

The listener serves HTTP and does not authenticate requests. Bind it to loopback for local access, or keep it on a
private network behind an authenticated proxy and prevent direct access. Do not expose it through the public service
ingress. The sequencer and validator use their existing administration listeners, which also serve their other admin
operations.

### Example: change and restore a filter

For the commands below, set the shell variable `ADMIN_URL` to the administration API's base URL:

```bash
ADMIN_URL=http://127.0.0.1:50100
```

List tracing targets to help choose which part of the service to investigate:

```bash
curl --fail-with-body "${ADMIN_URL}/admin/tracing/targets"
```

The response contains a `targets` array of names you can use in filter expressions, such as `miden::storage::sqlite`.
The list contains Miden's declared targets. Filters also accept targets absent from this list, including those used by
external dependencies.

Each update replaces the filter for one output using the same node and dependency levels described above. Reads return
the effective expression, including the dependency baseline and expanded `miden::` alias. Save the current filter so you
can restore it after the investigation:

```bash
curl --fail-with-body "${ADMIN_URL}/admin/tracing/stdout-filter" --output stdout-filter.json
curl --fail-with-body "${ADMIN_URL}/admin/tracing/otel-filter" --output otel-filter.json
```

Check that each request succeeds before proceeding. The saved JSON contains the active filter in the form
`{"filter":"<expression>"}` and can be sent back unchanged to restore it. If you only need stderr logs, skip the
OpenTelemetry request; it fails if exporting was disabled when the service started.

Replace the stderr filter with a complete expression:

```bash
curl --fail-with-body -X PUT "${ADMIN_URL}/admin/tracing/stdout-filter" \
  -H 'Content-Type: application/json' \
  --data '{"filter":"info,miden::storage::sqlite=debug"}'
```

Replace the OpenTelemetry filter independently:

```bash
curl --fail-with-body -X PUT "${ADMIN_URL}/admin/tracing/otel-filter" \
  -H 'Content-Type: application/json' \
  --data '{"filter":"info,miden::storage=debug"}'
```

A successful update returns `204 No Content`. Check stderr or your tracing backend for the expected detail from new
activity. Increasing verbosity does not recover earlier logs or traces. Updating the OpenTelemetry filter does not
enable exporting or change where traces are sent.

An invalid expression returns `400` and leaves the previous filter active. Correct the expression and retry. The
OpenTelemetry endpoints return `409` if exporting was disabled at startup; configure an exporter and restart before
reading or changing its filter. A `503` means tracing controls are unavailable, and a `500` means the filter could not
be read or updated. These handler errors return JSON with an `error` message. Correct request-shape errors, such as a
missing `filter` field, before retrying.

After the investigation, restore each filter you changed using its saved file:

```bash
curl --fail-with-body -X PUT "${ADMIN_URL}/admin/tracing/stdout-filter" \
  -H 'Content-Type: application/json' --data-binary @stdout-filter.json
curl --fail-with-body -X PUT "${ADMIN_URL}/admin/tracing/otel-filter" \
  -H 'Content-Type: application/json' --data-binary @otel-filter.json
```

To retain a filter across restarts, update the service's environment configuration. Environment variables are read only
during startup.

## Troubleshooting filters

Start with a narrow target instead of enabling `trace` globally:

```bash
# RPC request and subscription details
MIDEN_STDOUT_FILTER='info,user=debug,miden::storage=debug,miden::rpc::server=trace' miden-node full ...

# Chain synchronization details
MIDEN_STDOUT_FILTER='info,miden::sync=debug' miden-node full ...

# Block production and mempool details
MIDEN_STDOUT_FILTER='info,miden::production=debug,miden::mempool=debug' miden-node sequencer ...

# Store lifecycle and persistence details
MIDEN_STDOUT_FILTER='info,miden::storage=debug' miden-node full ...
```

Restart the service after changing a filter environment variable, or use the administration API to update the running
process.
