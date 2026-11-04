---
title: "Logging"
sidebar_position: 6
---

# Logging

All Miden node services write compact, structured logs to standard output. Long-running services can also export
OpenTelemetry traces. The stdout and OpenTelemetry outputs have independent filters, so operators can keep local logs
concise while retaining more detail in a tracing backend.

## Stdout filter

The stdout filter is selected from the first non-empty value in this order:

1. `MIDEN_STDOUT_FILTER`
2. `RUST_LOG`
3. `info,user=debug,miden::storage=debug,miden::rpc::server=debug,miden_prover=warn` (default)

`MIDEN_STDOUT_FILTER` uses the
[`tracing_subscriber` filter syntax](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html).
A filter is a comma-separated list of directives. Each directive sets a level globally or for a target:

```text
target=level
```

The available levels are `off`, `error`, `warn`, `info`, `debug`, and `trace`. Target directives match a target and its
children, so `user=info` applies to every `user::*` target.

For example, keep third-party and internal output at `warn`, show user-facing events at `info`, and enable detailed RPC
events:

```bash
MIDEN_STDOUT_FILTER='warn,user=info,miden::storage=info,miden::rpc::server=debug' \
miden-node full ...
```

To temporarily enable all debug logs:

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

`RUST_LOG` is a compatibility fallback. Prefer `MIDEN_STDOUT_FILTER` when configuring stdout independently from
OpenTelemetry.

## User-facing targets

Operator events use `user::*`, `miden::storage`, and `miden::rpc::server` targets. The default stdout filter enables
these at `debug`. The compact stdout format does not print the target name, but the filter still matches it.

`info` is intended for production use, such as on the sequencer of a Miden network, where detailed per-call or
per-transaction messages would create undesirable noise. Events whose primary use case is local development therefore
use the `debug` level, even when they are user-visible. The default stdout filter prints operator, storage, and RPC
server `debug` events, keeps shared RPC client diagnostics and other targets at `info`, and limits the `miden_prover`
dependency to `warn`.

| Target                        | Events                                                             |
| ----------------------------- | ------------------------------------------------------------------ |
| `user::miden-node`            | Node command startup, bootstrap, and recovery                      |
| `miden::rpc::server`          | RPC requests, subscriptions, readiness, and submissions            |
| `user::miden-block-producer`  | Sequencing, batches, blocks, mempool activity, and synchronization |
| `miden::storage`              | Persistence and account, note, and storage lifecycle events        |
| `user::miden-validator`       | Validator startup, bootstrap, validation, and block signing        |
| `user::miden-ntx-builder`     | Network transaction construction and account actor activity        |
| `user::miden-prover`          | Remote prover lifecycle events                                     |
| `user::miden-network-monitor` | Network monitor checks and end-to-end probes                       |
| `user::miden-funding-service` | Funding service readiness, funding transactions, and note commits  |

A `miden-node` process contains multiple components. For example, a sequencer can emit `user::miden-node`,
`miden::rpc::server`, `user::miden-block-producer`, and `miden::storage` events.

## OpenTelemetry filter

OpenTelemetry export is enabled when either `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` or `OTEL_EXPORTER_OTLP_ENDPOINT` has a
non-empty value. Its filter is selected independently from the first non-empty value in this order:

1. `MIDEN_OTEL_FILTER`
2. `RUST_LOG`
3. `info,axum::rejection=trace` (default)

For example, retain debug-level user-facing events in the tracing backend while keeping stdout quieter:

```bash
MIDEN_STDOUT_FILTER='warn,user=info,miden::storage=info,miden::rpc::server=info' \
MIDEN_OTEL_FILTER='info,user=debug,miden::storage=debug,miden::rpc::server=debug' \
OTEL_EXPORTER_OTLP_ENDPOINT=http://collector:4317 \
miden-node full ...
```

If neither Miden-specific filter is set, `RUST_LOG` configures both outputs. See
[Monitoring](/network-operator/monitoring) for exporter and resource configuration.

## Change filters while the service is running

The sequencer and validator administration APIs can replace either tracing filter without restarting the service. Use
this to collect more detail during an investigation, then restore your usual filter when finished. Updates affect only
the process receiving the request and last until its next restart.

Enable the private listener as described in
[Sequencer administration](/network-operator/sequencer#allowlist-administration) or
[Validator administration](/network-operator/validator#administration-api). Use the authenticated administration
endpoint provided by your deployment; the listener itself does not authenticate requests. Set `ADMIN_URL` to that
endpoint, for example:

```bash
ADMIN_URL=http://127.0.0.1:50100
```

List the available declared targets before choosing a filter:

```bash
curl --fail-with-body "${ADMIN_URL}/admin/tracing/targets"
```

The response is a JSON object with a sorted, unique `targets` array. It includes targets declared by components linked
into this build, even if their code has not run yet. Explicit callsite overrides, older instrumentation, and third-party
targets may also be used in expressions even when they do not appear in this list.

Fetch and save the current filters before changing them:

```bash
curl --fail-with-body "${ADMIN_URL}/admin/tracing/stdout-filter"
curl --fail-with-body "${ADMIN_URL}/admin/tracing/otel-filter"
```

Each successful `GET` returns `200` with `{"filter":"<expression>"}`. The expression represents the active filter;
directive ordering and formatting may differ from the original input without changing its meaning.

Replace the stdout filter with a complete expression:

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

A successful update returns `204 No Content`. Subsequent instrumentation uses the new filter; spans already created or
previously filtered out are not reconstructed. Changing a filter does not flush the exporter or change its endpoint.
Verify the expected new activity in stdout or your tracing backend. Coordinate updates with other operators: each
successful request replaces the selected output's entire expression.

An invalid expression returns `400` and leaves the previous filter active. Correct the expression and retry. The
OpenTelemetry endpoints return `409` if exporting was disabled at startup; configure an exporter and restart before
reading or changing its filter. A `503` means tracing controls are unavailable, and a `500` means the filter could not
be read or updated. These handler errors return JSON with an `error` message. Correct request-shape errors, such as a
missing `filter` field, before retrying.

Restore the usual expression with another `PUT` after the investigation. To retain a filter across restarts, also update
the service's environment configuration. Environment variables are read only during startup.

## Troubleshooting filters

Start with a narrow target instead of enabling `trace` globally:

```bash
# RPC request and subscription details
MIDEN_STDOUT_FILTER='info,user=debug,miden::storage=debug,miden::rpc::server=trace' miden-node full ...

# Block production and mempool details
MIDEN_STDOUT_FILTER='info,user::miden-block-producer=debug' miden-node sequencer ...

# Store lifecycle and persistence details
MIDEN_STDOUT_FILTER='info,miden::storage=debug' miden-node full ...
```

Restart the service after changing a filter environment variable, or use the administration API to update the running
process.
