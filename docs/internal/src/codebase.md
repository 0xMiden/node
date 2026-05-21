# Navigating the codebase

The code is organised using a Rust workspace with separate crates for the node and remote prover binaries, a crate for each node
component, a couple of gRPC-related codegen crates, and a catch-all utilities crate.

The primary execution artifacts are the node and remote prover binaries. The library crates are not intended for external usage, but
instead simply serve to enforce code organisation and decoupling.

We have a top-level `proto` crate, which contains the external and internal gRPC and protobuf schemas. It also exposes the 
`tonic`/`prost` file descriptors for each gRPC service for convenience. We then have an internal `proto` crate in `./crates`, 
which uses the above file descriptors to generate the actual service traits, and also defines some domain objects and other gRPC 
shared utilities and definitions.

> [!NOTE] > [`miden-protocol`](https://github.com/0xMiden/miden-protocol) is an important dependency which
> contains the core Miden protocol definitions e.g. accounts, notes, transactions etc.
