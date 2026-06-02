---
title: "Monitoring"
sidebar_position: 7
---

# Monitoring

Network operators can use `miden-network-monitor` and OpenTelemetry tracing to observe network health, RPC freshness,
validator status, prover status, and related infrastructure.

## Network Monitor

`miden-network-monitor` is an observer and test client. It is not required for block production. Depending on
configuration, it can check RPC freshness, validator health, remote prover status, faucet availability, explorer
availability, note transport, and end-to-end network transaction flows.

Use the binary help output for the current configuration surface:

```sh
miden-network-monitor start --help
```

## Telemetry

Node services use standard OpenTelemetry environment variables for trace export. The local compose telemetry overlay is
a useful reference for wiring services to an OTLP endpoint, but production deployments should use the operator's own
telemetry backend and retention policy.
