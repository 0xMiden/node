---
title: "Public RPC"
sidebar_position: 1
---

# Public RPC

This page summarizes the public gRPC `rpc.Api` service.

As a reminder, you can inspect the exact schema on any deployed network using gRPC reflection:

```bash
grpcurl rpc.testnet.miden.io:443 describe rpc.Api
```

## Status and Limits

| Method      | Purpose                                                                                                   |
| ----------- | --------------------------------------------------------------------------------------------------------- |
| `Status`    | Returns the node RPC version, genesis commitment, store status, and block producer status when available. |
| `GetLimits` | Returns configured query parameter limits for methods that accept large repeated parameters.              |

## State Queries

| Method                   | Purpose                                                                              |
| ------------------------ | ------------------------------------------------------------------------------------ |
| `GetAccount`             | Returns account witness data and optional details for public accounts.               |
| `GetBlockByNumber`       | Returns raw block data for a block number, optionally including the block proof.     |
| `GetBlockHeaderByNumber` | Returns a block header and, optionally, MMR authentication data and protocol config. |
| `GetNotesById`           | Returns committed notes matching the requested note IDs.                             |
| `GetNoteScriptByRoot`    | Returns a note script by script root when available.                                 |

## Transaction Submission

| Method                        | Purpose                                                                                     |
| ----------------------------- | ------------------------------------------------------------------------------------------- |
| `GetTransactionEncryptionKey` | Returns the transaction encryption public key, attested by a validator's signing key.       |
| `SubmitProvenTx`              | Submits one proven transaction and returns the node's current block height.                 |
| `SubmitProvenTxBatch`         | Submits an atomic batch of proven transactions and returns the node's current block height. |

Fetching the encryption key is a **required first step** before submitting. Both submit methods carry their private
transaction inputs sealed against that key, and a submission with missing or unsealable inputs is rejected. For a batch,
each transaction's inputs are sealed independently against that transaction's own id.

The public key returned by `GetTransactionEncryptionKey` is shared across the whole validator set, while each
attestation is specific to one validator (currently the response carries a single attestation). Clients verify an
attestation against a validator signing key they already trust from the chain and reconstruct the encryption key with
miden-crypto. The exact attestation payload, and the associated data that binds a sealed submission to one key, one
network and one transaction, are documented on the `TransactionEncryptionKey` and `SealedTransactionInputs` proto
messages.

Write requests must identify the target network with the `genesis` parameter in the `Accept` header:

```text
application/vnd.miden; genesis=<genesis-commitment>
```

Clients may also include a compatible RPC version:

```text
application/vnd.miden; version=<semver>; genesis=<genesis-commitment>
```

See [Errors and Limits](./errors-and-limits.md#transaction-submission-errors) for the transaction submission detail
codes returned in gRPC status details.

## State Synchronization

| Method                   | Purpose                                                                                 |
| ------------------------ | --------------------------------------------------------------------------------------- |
| `SyncTransactions`       | Returns transaction records for specified accounts within a block range.                |
| `SyncNotes`              | Returns note metadata and inclusion proofs for matching note tags within a block range. |
| `SyncNullifiers`         | Returns nullifiers matching specified 16-bit prefixes within a block range.             |
| `SyncAccountVault`       | Returns public account vault updates within a block range.                              |
| `SyncAccountStorageMaps` | Returns public account storage map updates within a block range.                        |
| `SyncChainMmr`           | Returns the chain MMR delta, target header, and protocol config when required.          |

Use `GetLimits` to discover the maximum request sizes accepted by the node before batching large sync requests.

## Streaming

| Method              | Purpose                                                                               |
| ------------------- | ------------------------------------------------------------------------------------- |
| `BlockSubscription` | Streams committed blocks from `block_from`, replaying history before live blocks.     |
| `ProofSubscription` | Streams block proofs from `block_from`, replaying existing proofs before live proofs. |

These streams are the primary mechanism full nodes use to replicate chain data from an upstream source. They are also
useful for indexers, explorers, and other services that need an append-only view of network progress.

## Network Note Debugging

| Method                 | Purpose                                                                                    |
| ---------------------- | ------------------------------------------------------------------------------------------ |
| `GetNetworkNoteStatus` | Returns the lifecycle status of a network note tracked by the network transaction builder. |
