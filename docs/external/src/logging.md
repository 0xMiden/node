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
3. `info,user=debug` (default)

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
MIDEN_STDOUT_FILTER='warn,user=info,user::miden-rpc=debug' \
miden-node full ...
```

To temporarily enable all debug logs:

```bash
MIDEN_STDOUT_FILTER=debug miden-node full ...
```

To configure a container, pass the filter as an environment variable:

```bash
docker run --rm \
  -e MIDEN_STDOUT_FILTER='warn,user=info,user::miden-rpc=debug' \
  ghcr.io/0xmiden/miden-node:<release-tag> \
  miden-node full ...
```

For systemd, set the same value in the service unit or an environment file, then restart the service:

```ini
[Service]
Environment="MIDEN_STDOUT_FILTER=warn,user=info,user::miden-rpc=debug"
```

`RUST_LOG` is a compatibility fallback. Prefer `MIDEN_STDOUT_FILTER` when configuring stdout independently from
OpenTelemetry.

## User-facing targets

The `user::*` targets contain events intended for operators. They are enabled at `debug` by the default stdout filter.
The compact stdout format does not print the target name, but the filter still matches it.

`info` is intended for production use, such as on the sequencer of a Miden network, where detailed per-call or
per-transaction messages would create undesirable noise. Events whose primary use case is local development therefore
use the `debug` level, even when they are user-visible. The default `info,user=debug` stdout filter keeps production
events at `info` while still printing user-visible `debug` events.

| Target                        | Events                                                             |
| ----------------------------- | ------------------------------------------------------------------ |
| `user::miden-node`            | Node command startup, bootstrap, and recovery                      |
| `user::miden-rpc`             | Public RPC requests, subscriptions, readiness, and submissions     |
| `user::miden-block-producer`  | Sequencing, batches, blocks, mempool activity, and synchronization |
| `user::miden-store`           | Persistence and account, note, and storage lifecycle events        |
| `user::miden-validator`       | Validator startup, bootstrap, validation, and block signing        |
| `user::miden-ntx-builder`     | Network transaction construction and account actor activity        |
| `user::miden-prover`          | Remote prover lifecycle events                                     |
| `user::miden-network-monitor` | Network monitor checks and end-to-end probes                       |
| `user::miden-funding-service` | Funding service readiness, funding transactions, and note commits  |

A `miden-node` process contains multiple components. For example, a sequencer can emit `user::miden-node`,
`user::miden-rpc`, `user::miden-block-producer`, and `user::miden-store` events.

## OpenTelemetry filter

OpenTelemetry export is enabled when either `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` or `OTEL_EXPORTER_OTLP_ENDPOINT` has a
non-empty value. Its filter is selected independently from the first non-empty value in this order:

1. `MIDEN_OTEL_FILTER`
2. `RUST_LOG`
3. `info,axum::rejection=trace` (default)

For example, retain debug-level user-facing events in the tracing backend while keeping stdout quieter:

```bash
MIDEN_STDOUT_FILTER='warn,user=info' \
MIDEN_OTEL_FILTER='info,user=debug' \
OTEL_EXPORTER_OTLP_ENDPOINT=http://collector:4317 \
miden-node full ...
```

If neither Miden-specific filter is set, `RUST_LOG` configures both outputs. See
[Monitoring](/network-operator/monitoring) for exporter and resource configuration.

## Troubleshooting filters

Start with a narrow target instead of enabling `trace` globally:

```bash
# RPC request and subscription details
MIDEN_STDOUT_FILTER='info,user=debug,user::miden-rpc=trace' miden-node full ...

# Block production and mempool details
MIDEN_STDOUT_FILTER='info,user::miden-block-producer=debug' miden-node sequencer ...

# Store lifecycle and persistence details
MIDEN_STDOUT_FILTER='info,user::miden-store=debug' miden-node full ...
```

Filters are read only during process startup. Restart the service after changing an environment variable.
