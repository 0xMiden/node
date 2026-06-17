---
title: "gRPC API"
sidebar_position: 0
---

# gRPC API

Miden nodes expose a public gRPC API for querying chain state, synchronizing local state, submitting proven
transactions, and subscribing to committed blocks and block proofs.

The API uses standard gRPC status codes. Some methods also include additional Miden-specific error codes in status
details for stable client-side handling.

See [Official Network URLs](/official-network-urls) for public RPC endpoints on official networks.

## Schema

The safest way to inspect the schema for a deployed network is through gRPC reflection:

```bash
grpcurl rpc.testnet.miden.io:443 describe rpc.Api
```

For a local development network without TLS, use `-plaintext`:

```bash
grpcurl -plaintext localhost:57291 describe rpc.Api
```

For Rust developers, we also ship a Rust crate
[miden_node_proto_build](https://docs.rs/miden-node-proto-build/latest/miden_node_proto_build/) which exposes the gRPC
schemas as file descriptor sets, which can be used to generate the gRPC bindings using [tonic](https://docs.rs/tonic).

The source schema files are also available in the [Miden node repository](https://github.com/0xMiden/node), in the
`proto/` directory. If you use the repository source instead of reflection, check out the release tag that matches the
network or client version you are targeting. Branches such as `next` describe repository state, not necessarily the
schema deployed on an official network.

## Protocol Support

The RPC server supports:

- gRPC over HTTP/2.
- gRPC-Web.
- gRPC reflection for discovery tools such as `grpcurl`.

## Endpoint Groups

| Group                  | Methods                                                                                                         |
| ---------------------- | --------------------------------------------------------------------------------------------------------------- |
| Status and limits      | `Status`, `GetLimits`                                                                                           |
| State queries          | `GetAccount`, `GetBlockByNumber`, `GetBlockHeaderByNumber`, `GetNotesById`, `GetNoteScriptByRoot`               |
| Transaction submission | `SubmitProvenTx`, `SubmitProvenTxBatch`                                                                         |
| State synchronization  | `SyncTransactions`, `SyncNotes`, `SyncNullifiers`, `SyncAccountVault`, `SyncAccountStorageMaps`, `SyncChainMmr` |
| Block streaming        | `BlockSubscription`, `ProofSubscription`                                                                        |
| Network note debugging | `GetNetworkNoteStatus`                                                                                          |

See [Public RPC](/rpc/public-api) for endpoint summaries, [Subscriptions](/rpc/subscriptions) for stream semantics, and
[Errors and Limits](/rpc/errors-and-limits) for request limits, content negotiation, and method-specific error codes.
