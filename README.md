# Miden node

[![LICENSE](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/0xMiden/node/blob/main/LICENSE)
[![CI](https://github.com/0xMiden/node/actions/workflows/ci.yml/badge.svg)](https://github.com/0xMiden/node/actions/workflows/ci.yml)
[![RUST_VERSION](https://img.shields.io/badge/rustc-1.93+-lightgray.svg)](https://www.rust-lang.org/tools/install)
[![crates.io](https://img.shields.io/crates/v/miden-node)](https://crates.io/crates/miden-node)

This repository contains the core infrastructure components of a Miden network, including the node
implementation. The workspace includes binaries and component crates for block production,
validation, state storage, public RPC serving, network transaction building, proving services, and
monitoring.

The Miden node is still under active development and should be treated as alpha software. The current
implementation is designed around a centralized operator; P2P networking and consensus are not part
of this repository yet.

## Documentation

Node documentation for current official testnet versions is available in the official Miden docs at
<https://docs.miden.xyz/core-concepts/node/>. Network operators, full-node runners, and builders
looking to run a local Miden network should prefer those docs.

Documentation for the current repository version is published from this repository:

- Node and operator documentation: <https://0xMiden.github.io/node/index.html>
- Developer documentation: <https://0xMiden.github.io/node/developer/index.html>

The formal public RPC protobuf definition for this repository version is
[`proto/proto/rpc.proto`](./proto/proto/rpc.proto).

The rest of this README is intended for developers working in this repository.

## Workspace Entry Points

The workspace is organized around several binaries:

- [`miden-node`](https://crates.io/crates/miden-node): the main node binary. It runs a sequencer or a
  full node and embeds the store, RPC, and block-producer components.
- [`miden-validator`](https://crates.io/crates/miden-validator): validates transactions and proposed
  blocks, signs valid blocks, and creates the signed genesis block during bootstrap.
- [`miden-ntx-builder`](https://crates.io/crates/miden-ntx-builder): follows committed blocks and
  builds network transactions for network accounts.
- [`miden-remote-prover`](https://crates.io/crates/miden-remote-prover): runs a gRPC proving service
  for transaction, batch, or block proofs.
- [`miden-network-monitor`](https://crates.io/crates/miden-network-monitor): monitors node,
  validator, prover, faucet, explorer, and note-transport infrastructure.

Each binary exposes its supported commands and configuration through its help output. Prefer the
binary help output over copied command snippets, since configuration changes more often than the
high-level architecture.

## Core Components

The component crates exist primarily to support the binaries and are not intended
as libraries for other development.

- `miden-node-store`: persistent chain state and database-backed store logic used by `miden-node`.
- `miden-node-rpc`: public RPC server frontend of `miden-node`.
- `miden-node-block-producer`: block production implementation used by `miden-node` in sequencer
  mode.
- `miden-node-proto`: generated protobuf bindings and conversion code.
- `miden-node-proto-build`: protobuf file descriptors for generating gRPC clients.
- `miden-node-db`, `miden-node-utils`, and related helper crates: shared infrastructure for the
  workspace.

## Development

Use the developer documentation for architecture notes, component internals, testing workflows, and
local development setup. Repository READMEs are landing pages for crates and binaries; operational
instructions should live in the documentation rather than in copied command examples.

## Contributing

Please read the [contributing guidelines](https://github.com/0xMiden/.github?tab=contributing-ov-file)
before opening a pull request. PRs may be closed unless they are associated with an issue assigned by
a maintainer.

For typos and documentation errors, please open an issue rather than a drive-by pull request.

## License

This project is [MIT licensed](./LICENSE).
