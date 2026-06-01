# Miden node

[![LICENSE](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/0xMiden/node/blob/main/LICENSE)
[![CI][ci-badge]][ci-link]
[![RUST_VERSION](https://img.shields.io/badge/rustc-1.93+-lightgray.svg)](https://www.rust-lang.org/tools/install)
[![crates.io](https://img.shields.io/crates/v/miden-node)](https://crates.io/crates/miden-node)

[ci-badge]: https://github.com/0xMiden/node/actions/workflows/ci.yml/badge.svg
[ci-link]: https://github.com/0xMiden/node/actions/workflows/ci.yml
[developer-docs]: https://0xMiden.github.io/node/index.html

This repository contains the core infrastructure components of a Miden network, including the sequencer and full node
implementations. It also defines the public gRPC API for interfacing with the network.

Miden is still under active development. The components in this repository, including the RPC schema,
should be treated as unstable. The current network design remains centralized while the proving
system and protocol mature.

## Documentation

Node documentation for official testnet versions is available as part of the official Miden docs at
<https://docs.miden.xyz/core-concepts/node/>. This includes guides for network operators,
full node runners, and builders looking to run a local Miden network.

The gRPC schema can be found in the top-level [`proto`](./proto) directory. Note that this will
reflect the current development state, and one should look to the official docs for network schemas.

The rest of this README is intended for developers in this repository. Advanced users
and the curious may get some further value from it. If any information is missing from the
official documentation, please open an issue.

## Developer docs

Developers can find repository and onboarding documentation in the [developer docs][developer-docs].
Those docs are more in-depth but the following sections endeavour to provide a short summary.

### Workspace organisation

The workspace is organised around several binaries, with supplementary crates providing
organisation and shared functionality. These crates are for internal use only; the primary
outputs are the binaries and gRPC schema. The former are found under the `bin`
directory, the latter in the `proto` directory.

#### Binaries

A quick overview of the binaries:

- [`node`](./bin/node/README.md): the node binary which can operate in either sequencer or full node
  configuration.
- [`validator`](./bin/validator/README.md): independent verification of proposed blocks before they
  may be committed on chain.
- [`ntx-builder`](./bin/ntx-builder/README.md): monitors blocks for network notes, and creates
  network transactions consuming these.
- [`remote-prover`](./bin/remote-prover/README.md): provides a FIFO service for proving
  transactions, batches, and blocks.
- [`network-monitor`](./bin/network-monitor/README.md): a tool which monitors a network's
  infrastructure, e.g. block production, RPC, validator, prover, faucet, explorer, and note
  transport.

There are additional binaries but they're more supplementary; see their READMEs for more information.

#### gRPC

The [gRPC schema](./proto/README.md) falls into two buckets: the primary public
[RPC API](./proto/proto/rpc.proto) and [remote prover API](./proto/proto/remote_prover.proto), and
the [internal schemas](./proto/proto/internal) used to communicate between internal network services.

#### Workspace crates

The crates exist primarily to support the binaries and are not intended
as libraries for external development.

- `store`: persistent chain state and database-backed store logic used by the `node`.
- `rpc`: public RPC server frontend of the `node`.
- `block-producer`: handles block sequencing and block syncing for the node.
- `proto`: uses gRPC bindings from the schema for both RPC and internal services.
- `db`: common framework for SQLite migrations and interactions.
- `utils`: catch-all common utilities.

## Development

The [developer documentation][developer-docs] provides the architectural design of the node and other
binaries.

For testing and other workflows, please see the `Makefile`. The more frequently used commands are:

```sh
# Note: we use +nightly for formatting, so using general `cargo fmt` will conflict.
make format
make lint
make test
```

Our CI enforces consistency here so it would be good to familiarize yourself with
at least our [CI GitHub jobs](./.github/workflows/ci.yml).

## Contributing

Please read the [contributing guidelines](https://github.com/0xMiden/.github?tab=contributing-ov-file)
before opening a pull request. PRs may be closed unless they are associated with an issue assigned by
a maintainer.

For typos and documentation errors, please open an issue rather than a drive-by pull request.

## License

This project is [MIT licensed](./LICENSE).
