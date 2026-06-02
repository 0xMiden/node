---
title: "gRPC API"
sidebar_position: 0
---

# gRPC API

Miden nodes expose a public gRPC API for querying chain state, synchronizing local state, submitting
proven transactions, and subscribing to committed blocks and block proofs.

The public service definition lives in the node repository at `proto/proto/rpc.proto`. The same
service is exposed by sequencers and full nodes:

- A sequencer RPC serves canonical network state and submits accepted transactions into block
  production.
- A full-node RPC serves locally replicated state and forwards transaction submissions to its
  configured upstream RPC source.

Full nodes do not produce blocks.

## Protocol Support

The RPC server supports:

- gRPC over HTTP/2.
- gRPC-Web.
- gRPC reflection for discovery tools such as `grpcurl`.

For local development, once the compose stack is running:

```sh
grpcurl -plaintext localhost:57291 rpc.Api/Status
```

## Endpoint Groups

| Group | Methods |
|---|---|
| Status and limits | `Status`, `GetLimits` |
| State queries | `GetAccount`, `GetBlockByNumber`, `GetBlockHeaderByNumber`, `GetNotesById`, `GetNoteScriptByRoot` |
| Transaction submission | `SubmitProvenTx`, `SubmitProvenTxBatch` |
| State synchronization | `SyncTransactions`, `SyncNotes`, `SyncNullifiers`, `SyncAccountVault`, `SyncAccountStorageMaps`, `SyncChainMmr` |
| Streaming | `BlockSubscription`, `ProofSubscription` |
| Network note debugging | `GetNetworkNoteStatus` |

See [Public RPC](./public-api) for endpoint summaries, [Subscriptions](./subscriptions) for stream
semantics, and [Errors and Limits](./errors-and-limits) for request limits and content negotiation.
