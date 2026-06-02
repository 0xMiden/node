---
title: "Local Node Development"
sidebar_position: 1
---

# Local Node Development

Use the repository's Docker Compose files to run a local, disposable Miden network for development and testing. This
setup starts a local sequencer and its supporting services. It is not a production deployment guide and it is not the
path for independent full node runners on an existing network.

The compose files are not distributed by `docker pull`. Use a repository checkout so the compose files, Dockerfiles,
source code, and example configuration all come from the same version.

## Prerequisites

- Git
- Docker with Docker Compose support
- `make`

## Check Out a Version

Prefer a release tag when testing against released artifacts. Use a branch when developing against the current
repository state.

```sh
git clone https://github.com/0xMiden/node.git
cd node
git checkout <release-tag-or-branch>
```

## Start the Local Network

Build the local Docker images and start the default development stack:

```sh
make docker-build
make compose-up
```

The default `compose-up` target starts the base node services plus the telemetry and network monitor overlays.

Follow logs:

```sh
make compose-logs
```

Stop containers without deleting the local chain data volume:

```sh
make compose-down
```

## Base Compose File

For the smallest local network, run only the base compose file:

```sh
make docker-build
docker compose -f docker-compose.yml up -d
```

The base network starts:

| Service                 | Role                                                               | Public port |
| ----------------------- | ------------------------------------------------------------------ | ----------: |
| `bootstrap-validator`   | Creates and signs genesis, then initializes the validator database |        None |
| `bootstrap-node`        | Initializes node storage from the signed genesis block             |        None |
| `bootstrap-ntx-builder` | Initializes network transaction builder storage from genesis       |        None |
| `sequencer`             | Runs `miden-node sequencer` and serves the public RPC API          |     `57291` |
| `validator`             | Validates transactions and signs blocks for the sequencer          |        None |
| `ntx-builder`           | Builds network transactions from network notes                     |        None |

## Optional Compose Extensions

The `compose/` directory contains optional overlays:

```sh
# Base network with telemetry.
docker compose -f docker-compose.yml -f compose/telemetry.yml up -d

# Base network with the network monitor.
docker compose -f docker-compose.yml -f compose/monitor.yml up -d

# Base network with telemetry and the network monitor.
docker compose -f docker-compose.yml -f compose/telemetry.yml -f compose/monitor.yml up -d
```

The telemetry overlay starts Tempo and Grafana. The monitor overlay starts the Miden network monitor.

| Service         | URL                      |
| --------------- | ------------------------ |
| Sequencer RPC   | `http://localhost:57291` |
| Grafana         | `http://localhost:3000`  |
| Network monitor | `http://localhost:3001`  |
| Tempo HTTP API  | `http://localhost:3200`  |
| Tempo OTLP gRPC | `http://localhost:4317`  |

## Bootstrap and Local Data

The compose stack stores local network data in the `node-data` Docker volume. Bootstrap containers write marker files
into this volume so repeated starts reuse the existing local chain.

To destroy the local chain and bootstrap from a fresh genesis block, stop the stack and remove the volume:

```sh
docker compose -f docker-compose.yml -f compose/telemetry.yml -f compose/monitor.yml down -v --remove-orphans
make compose-up
```

This deletes the local development network state.

## Check the RPC API

The RPC server exposes gRPC reflection. With `grpcurl` installed, a basic status check looks like:

```sh
grpcurl -plaintext localhost:57291 rpc.Api/Status
```

Use the [gRPC API](./rpc/) section for the public RPC surface and streaming endpoints.

## Production Difference

The compose stack is useful for local connectivity and client testing because it shows how the sequencer, validator, and
network transaction builder connect. Network operators should treat it as a local reference only, not as a production
deployment model.
