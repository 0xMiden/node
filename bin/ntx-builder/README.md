# Miden network transaction builder

`miden-ntx-builder` is a Miden node binary that creates network transactions for network accounts.
It is part of the Miden node repository; see the
[repository README](https://github.com/0xMiden/node#readme) for the overall project layout.

## Role

The network transaction builder syncs blocks from an upstream node, tracking network
notes and accounts.
It starts per-account workers for network accounts with pending work. Each worker selects
viable notes, constructs a transaction, proves it, and submits the proven transaction back through
the upstream node's RPC API.

The builder can use a remote transaction prover through `miden-remote-prover`, or fall back to
in-process proving where appropriate for local development. It also exposes an internal gRPC API that
the node RPC component can use for network-note status queries.

## Operation

The builder has its own persistent database and must be initialized from the same trusted genesis
block as the rest of the network before it starts. In a complete node deployment, `node`
connects to this service so network-note status can be exposed through the public RPC API.

## License

This project is [MIT licensed](../../LICENSE).
