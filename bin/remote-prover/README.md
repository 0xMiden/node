# Miden remote prover

A gRPC server which provides a service for proving either transactions, batches or blocks for the Miden blockchain.

This enables weaker devices to offload the proof generation to a beefy remote server running this service.

The implementation provides a configurable request queue and proves one request at a time in FIFO order. This is not intended to cover
complex proxy setups nor load-balancing, but can instead be used as a starting point for more advanced setups.

The gRPC specification can be found in the [Miden repository](https://github.com/0xMiden/miden-node/blob/main/proto/proto/remote_prover.proto).
Ensure you are viewing the appropriate version tag or commit.

## Quick start

```bash
# Install the binary.
cargo install miden-remote-prover --locked

# and start as a transaction prover.
miden-remote-prover   \
  --kind transaction  \ # Specify the kind of proof to generate (transaction, batch, or block)
  --port 50051
```

In a separate terminal, inspect the available services using grpcurl and reflection.

```bash
grpcurl -plaintext localhost:50051 list
```

or query the status of the prover.

```bash
grpcurl -plaintext localhost:50051 remote_prover.WorkerStatusApi/Status
```

## Installation

### Debian package

Install the Debian package:

```bash
set -e

sudo wget https://github.com/0xMiden/miden-node/releases/download/v0.8/miden-prover-v0.8-arm64.deb -O prover.deb
sudo wget -q -O - https://github.com/0xMiden/miden-node/releases/download/v0.8/miden-prover-v0.8-arm64.deb.checksum | awk '{print $1}' | sudo tee prover.checksum
sudo sha256sum prover.deb | awk '{print $1}' > prover.sha256
sudo diff prover.sha256 prover.checksum
sudo dpkg -i prover.deb
sudo rm prover.deb
```

Edit the configuration file `/lib/systemd/system/miden-prover.service.env`

Run the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable miden-prover
sudo systemctl start miden-prover
```

### From source 

To build the service from a local version, from the root of the workspace you can run:

```bash
make install-remote-prover
```

The CLI can be installed from the source code using specific git revisions with `cargo install` or from crates.io with `cargo install miden-remote-prover`.

## Configuration

Quick start:

```bash
miden-remote-prover --kind transaction
```

The prover can be further configured from the command line or using environment variables as per the help message:

```bash
> miden-remote-prover --help

Usage: miden-remote-prover [OPTIONS] --kind <KIND>

Options:
      --port <PORT>
          The port the gRPC server will be hosted on

          [env: MIDEN_PROVER_PORT=]
          [default: 50051]

      --kind <KIND>
          The proof type that the prover will be handling

          [env: MIDEN_PROVER_KIND=]
          [possible values: transaction, batch, block]

      --timeout <TIMEOUT>
          Maximum time allowed for a proof request to complete. Once exceeded, the request is aborted

          [env: MIDEN_PROVER_TIMEOUT=]
          [default: 60s]

      --capacity <CAPACITY>
          Maximum number of concurrent proof requests that the prover will allow.

          Note that the prover only proves one request at a time; the rest are queued. 
          This capacity is used to limit the number of requests that can be queued at any given time, 
          and includes the one request that is currently being processed.

          [env: MIDEN_PROVER_CAPACITY=]
          [default: 1]

  -h, --help
          Print help (see a summary with '-h')
```

## Status, health and monitoring

The server implements the following health and status related gRPC services:

- [gRPC Health Check](https://grpc.io/docs/guides/health-checking/)
- [gRPC Reflection](https://grpc.io/docs/guides/reflection/) 
- [WorkerStatusApi](https://github.com/0xMiden/miden-node/blob/main/proto/proto/remote_prover.proto)

The server supports OpenTelemetry traces which can be configured using the environment variables specified in the OpenTelemetry documentation.

For example, to send the traces to [HoneyComb](https://www.honeycomb.io/):

```bash
OTEL_SERVICE_NAME=miden-remote-prover
OTEL_EXPORTER_OTLP_ENDPOINT=https://api.honeycomb.io
OTEL_EXPORTER_OTLP_HEADERS=x-honeycomb-team=<api-key>
```

A self-hosted alternative is [Jaeger](https://www.jaegertracing.io/).

## License

This project is [MIT licensed](../../LICENSE).
