---
title: "Configuration"
sidebar_position: 7
---

# Configuration

Required options:

| Option                    | Purpose                                                  |
| ------------------------- | -------------------------------------------------------- |
| `--data-directory`        | Directory containing local node state.                   |
| `--rpc.listen`            | Socket address for the local public RPC API.             |
| `--sync.block-source.url` | Upstream RPC URL used for block and proof subscriptions. |

The rest have sensible default values which should only be tweaked for specific reasons. Use the command help output for
the complete current configuration surface.

Most options also have environment variable forms, which are useful when running under an orchestrator.

## OpenTelemetry Traces

Full nodes can export OpenTelemetry traces using the standard OTLP environment variables. Trace export is enabled when
either of these variables is set to a non-empty value:

- `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`
- `OTEL_EXPORTER_OTLP_ENDPOINT`

For example:

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://collector:4317 \
OTEL_RESOURCE_ATTRIBUTES=service.instance.id=full-node-1 \
miden-node full \
  --data-directory full-node-data \
  --rpc.listen 127.0.0.1:57291 \
  --sync.block-source.url http://upstream-node:57291
```

Use `OTEL_RESOURCE_ATTRIBUTES=service.instance.id=<node-id>` to identify a specific node instance in your tracing
backend. Other standard OpenTelemetry environment variables, such as `OTEL_SERVICE_NAME`, can be used to override the
service name when needed.
