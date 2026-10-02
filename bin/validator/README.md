# Miden validator

`miden-validator` is a Miden node binary that validates network activity before blocks are committed. It is part of the
Miden node repository; see the [repository README](https://github.com/0xMiden/node#readme) for the overall project
layout.

## Role

The validator is separate from `node` so that block construction and block validation can be operated as distinct
services. It verifies submitted transactions, validates proposed blocks, and signs blocks that satisfy the validator's
checks.

The validator binary is also responsible for creating the genesis block, via its `genesis` command. The genesis block is
not signed; it commits to the validator set that must sign every subsequent block, and is then used to initialize the
validators, the node, and other services that need trusted genesis state.

## Operation

The validator expects to operate as an internal service within a Miden network's infrastructure and exposes a gRPC API
for use by trusted internal nodes.

It supports local development keys and KMS-backed signing for deployments that need external key management.

## Peer-to-peer DKG

`miden-validator dkg participate` connects directly to peers by default, without public relays or address discovery.
Supply each peer as `--peer.endpoint <ENDPOINT_ID>@<IP:PORT>` and choose the local UDP listening address with
`--bind-address <IP:PORT>`. Loopback addresses allow a local ceremony without internet access.

Use `--enable-public-relay` on each participant to opt into n0's public Iroh relays and address discovery. Peer socket
addresses then become optional: `--peer.endpoint <ENDPOINT_ID>` is sufficient. Direct connections remain available, with
encrypted relay transport as a fallback. The public relays are intended for development and testing, not guaranteed
production availability.

Each participant supplies its persistent identity with `--endpoint-secret <FILE>`. Regardless of the connection route,
peers must authenticate with their genesis validator keys.

## License

This project is [MIT licensed](../../LICENSE).
