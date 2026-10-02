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

`miden-validator dkg participate` requires `--relay.url <URL>`. All ceremony participants must use the same dedicated
Iroh relay. Use an HTTPS URL for a deployment, or an HTTP URL such as `http://127.0.0.1:3340` for a local
`iroh-relay --dev` process. The validator does not use public Iroh endpoint discovery or default relays.

Each participant also supplies its persistent identity with `--endpoint-secret <FILE>` and the other participants with
repeated `--peer.endpoint <ENDPOINT_ID>` arguments. The shared relay routes connections to those endpoint IDs. Peers
must still authenticate with their genesis validator keys. Direct UDP connections remain available, but the ceremony can
use the relay for all traffic. Validators only need outbound access to the relay for connectivity.

## License

This project is [MIT licensed](../../LICENSE).
