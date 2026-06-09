---
title: "Local Network Development"
sidebar_position: 1
---

# Local Network Development

Use this guide to start a disposable Miden network for local development and testing. The provided Docker Compose setup
includes the local network, monitoring, and trace collection, so you can develop against a working environment without
wiring the network services manually.

The compose files live in the repository: `docker-compose.yml` in the root and supporting files under `compose/`. The
guide uses `make` targets as shorthand for the underlying Docker image builds and Docker Compose commands; check the
`Makefile` when you need the exact command.

This is not a production deployment guide and it is not the path for independent full node runners on an existing
network.

## Prerequisites

- Git
- Docker with Docker Compose support
- `make`

## Check Out a Version

Prefer a release tag when testing against released artifacts. Use a branch when developing against the current
repository state.

```bash
git clone https://github.com/0xMiden/node.git
cd node
git checkout <release-tag-or-branch>
```

## Local Network Commands

Build the images after checkout or whenever you need fresh local images. The local network stores data in the
`node-data` Docker volume; `local-network-down` keeps that data, while `local-network-delete` removes it.

```bash
# Build the Docker images used by the local network.
make local-network-build

# Optionally build for a specific Docker platform.
make local-network-build DOCKER_PLATFORM=linux/arm64

# Start the local network.
make local-network-up

# Follow container logs.
#
# Logs are useful for startup checks; use Tempo traces for request-level debugging.
make local-network-logs

# Stop the local network, preserving the local chain data volume.
make local-network-down

# Stop the local network and delete the local chain data volume.
make local-network-delete
```

After `make local-network-delete`, run `make local-network-up` to bootstrap a fresh local chain.

## Exposed Endpoints

Published ports are bound to `localhost`; the following services are available:

| Service         | URL                      | Purpose                                          |
| --------------- | ------------------------ | ------------------------------------------------ |
| RPC API         | `http://localhost:57291` | Submit transactions and query local chain state. |
| Grafana         | `http://localhost:3000`  | Inspect dashboards and traces.                   |
| Network monitor | `http://localhost:3001`  | View local network health.                       |
| Tempo HTTP API  | `http://localhost:3200`  | Query stored trace data.                         |
| Tempo OTLP gRPC | `http://localhost:4317`  | Receive OpenTelemetry traces from services.      |

## Monitoring and Traces

The local network exports OpenTelemetry traces to Tempo. Grafana is preconfigured with Tempo as a data source, so use
`http://localhost:3000` to inspect traces when a request fails, stalls, or behaves differently than expected.

Container logs are still useful for startup failures and quick checks, but traces usually provide a better view of how a
request moved through the local network.

The network monitor at `http://localhost:3001` provides a compact health view for the running local network.

## Prover Override

The default stack spins up an internal prover instance which means proving will happen locally. This can be overridden
to use an external prover by setting `MIDEN_REMOTE_PROVER_URL` when starting the stack. The URL must be reachable from
inside the Compose network.

```bash
MIDEN_REMOTE_PROVER_URL=http://<prover-host>:50051 make local-network-up
```

## Genesis Config Override

By default, the local network bootstraps from the validator's built-in genesis configuration. To bootstrap from a custom
genesis configuration file, set `MIDEN_GENESIS_CONFIG_FILE` to the host path of the TOML file:

```bash
MIDEN_GENESIS_CONFIG_FILE=/absolute/path/to/genesis.toml make local-network-up
```

The override bind mounts the host file into the bootstrap validator container as `/genesis.toml` and passes that
in-container path to `miden-validator bootstrap --genesis-config-file`.

This only affects validator bootstrap. If the local network has already been bootstrapped, delete the existing local
chain data before starting with a different genesis configuration:

```bash
make local-network-delete
```

## Check the RPC API

The RPC server exposes gRPC reflection. With `grpcurl` installed, a basic status check looks like:

```bash
grpcurl -plaintext localhost:57291 rpc.Api/Status
```

Note the `-plaintext` flag, the local network does not use TLS.

Use the [gRPC API](./rpc/) section for the public RPC surface and streaming endpoints.
