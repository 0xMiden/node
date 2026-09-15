---
title: "Monitoring"
sidebar_position: 8
---

# Monitoring

Network operators can use `miden-network-monitor` and OpenTelemetry tracing to observe network health, RPC freshness,
validator status, prover status, and related infrastructure.

See [Logging](/logging) for stdout filtering, filter precedence, user-facing targets, and separate OpenTelemetry filter
configuration.

## Network Monitor

`miden-network-monitor` is an observer and test client. It is not required for block production. Depending on
configuration, it can check RPC freshness, validator health, remote prover status, faucet availability, explorer
availability, note transport, and end-to-end network transaction flows.

End-to-end transaction checks require the validator's signing public key. Set
`MIDEN_MONITOR_VALIDATOR_SIGNING_PUBLIC_KEY` to the validator key's hex encoding. The monitor uses this key to verify
the validator's transaction encryption key before it submits private inputs. It obtains the active fee asset from RPC
and verifies the returned protocol configuration against each transaction's reference block. Remote transaction-prover
probes use the same RPC configuration discovery.

Use the binary help output for the current configuration surface:

```bash
miden-network-monitor start --help
```

## Telemetry

Services export OpenTelemetry traces when an OTLP trace endpoint is configured through the standard OpenTelemetry
environment variables.

Set one of:

- `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`
- `OTEL_EXPORTER_OTLP_ENDPOINT`

Services register a default OpenTelemetry service name and the `miden` service namespace. To distinguish multiple
instances of the same service, set `service.instance.id` through `OTEL_RESOURCE_ATTRIBUTES`.

For example:

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://collector:4317 \
OTEL_RESOURCE_ATTRIBUTES=service.instance.id=full-node-1 \
miden-node full ...
```

Other standard OpenTelemetry resource variables, such as `OTEL_SERVICE_NAME`, can still be used when an operator needs
to override the default service identity.
