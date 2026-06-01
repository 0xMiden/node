# Miden validator

`miden-validator` is a Miden node binary that validates network activity before blocks are committed.
It is part of the Miden node repository; see the
[repository README](https://github.com/0xMiden/node#readme) for the overall project layout.

## Role

The validator is separate from `node` so that block construction and block validation can be
operated as distinct services. It verifies submitted transactions, validates proposed blocks, and
signs blocks that satisfy the validator's checks.

The validator is also responsible for creating and signing the genesis block during bootstrap. That
signed genesis block is then used to initialize the node and other services that need trusted genesis
state.

## Operation

The validator expects to operate as an internal service within a Miden network's infrastructure and
exposes a gRPC API for use by trusted internal nodes.

It supports local development keys and KMS-backed signing for deployments that need external key
management.

## License

This project is [MIT licensed](../../LICENSE).
