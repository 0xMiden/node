---
title: "Public RPC"
sidebar_position: 1
---

# Public RPC

This page summarizes the public gRPC `miden.node.v1.NodeService` service.

As a reminder, you can inspect the exact schema on any deployed network using gRPC reflection:

```bash
grpcurl rpc.testnet.miden.io:443 describe miden.node.v1.NodeService
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

## Account Registration

`RegisterAccount` binds an invitation code to an account ID. Send the original code string in `invitation_code` and the
target account in `account_id`. Codes are case-sensitive. Send the code exactly as received, without trimming or
normalization. Registration does not create an account on chain.

Retrying the same code and account succeeds without changes. An unknown code returns `NOT_FOUND`. A code bound to
another account, or an account already registered with another entry, returns `ALREADY_EXISTS`. Invalid input returns
`INVALID_ARGUMENT`. These errors do not consume an invitation.

If allowlist enforcement is disabled, `RegisterAccount` accepts any invitation code, including an empty code. It adds
the account directly to the registry without storing or consuming the code. Existing invitations remain unchanged.
Repeating registration for the same account succeeds with any code and does not request funding again.

If the sequencer has registration funding configured, a new registration also requests a public P2ID funding note. The
call waits for the funding service to queue the note. A successful response does not confirm that the note committed.
Retrieve the note through the target account's note tag after it commits. A failed funding request returns
`UNAVAILABLE`, but the account remains registered and the invitation remains consumed. Repeating registration does not
request funding again. Contact the network operator if funding fails.

Include the network's `genesis` parameter in the `Accept` header, as for transaction submission. Use TLS when sending
invitation codes over a network. Do not log invitation codes. Full nodes forward registration to the sequencer.

`IsAccountAllowed` takes an account ID in `account_id` and returns `true` if allowlist enforcement is disabled or the
account is allowlisted. Full nodes forward this query to the sequencer.

## Transaction Submission

The sequencer requires registration before a transaction creates a non-network account. Transactions for existing
accounts and network-account creation do not require registration. An unregistered creation returns `PERMISSION_DENIED`.
If a batch contains an unregistered creation, the sequencer rejects the entire batch.

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

Authenticate the `SyncChainMmr` target header and its MMR delta first. Keep its block number `N` fixed for all other
requests in the attempt. Delta streams take `StateDeltaRange`: `from_block_exclusive = C` and `to_block_inclusive = N`
request `(C, N]`. Omit the lower bound to include genesis during bootstrap. The target is required. Equal bounds return
an empty delta after target validation. `SyncAccountVaultV2` also accepts the legacy inclusive `block_range`; send
exactly one range representation.

| Method                     | Purpose                                                                                          |
| -------------------------- | ------------------------------------------------------------------------------------------------ |
| `SyncChainMmr`             | Returns the chain MMR delta, authenticated target header, and required protocol config.          |
| `SyncAccountCommitments`   | Streams one target account witness for each changed tracked account, including private accounts. |
| `SyncNotesV2`              | Streams block frames and compact matching notes with target-anchored block paths.                |
| `SyncNullifiersV2`         | Streams every matching 16-bit-prefix consumption through the target.                             |
| `SyncAccountVaultV2`       | Streams the final target value of every changed vault key.                                       |
| `SyncAccountStorageMapsV2` | Streams the final target value of every changed storage-map key.                                 |
| `GetTransactionsById`      | Streams requested transactions committed at or before `target_block_num`.                        |
| `SyncTransactionsV2`       | Streams complete account transaction events in the requested range.                              |

Verify account witnesses against the target header's account root. Compare each proven commitment with the local account
header. Fetch `GetAccount` at `N` only for divergent accounts. Verify fetched details and the recomputed vault/storage
commitments before applying the update. Vault deletions have no asset. Storage-map deletions have a zero word.
`GetAccount` supplies slot changes, including removed slots, which map-key updates cannot describe.

`SyncNotesV2` sends a block frame exactly once before that block's notes. Reject notes before a block frame,
repeated/backward block frames, and note proofs for another block. Verify each note path against its block's note root
and each block path against the MMR with `N + 1` leaves, including the authenticated target header. Fetch public note
bodies and missing attachment content with `GetNotesById`. Reject malformed or incomplete records.

Use `GetTransactionsById` for locally pending or unconfirmed transaction IDs. Returned IDs committed by `N`. An ID
omitted from a successfully completed stream was not committed by `N`; omission alone does not mean expiration,
conflict, or permanent rejection. Continue separate expiration and conflict checks. This endpoint does not add a
transaction-inclusion proof. Keep the existing transaction-validation rules. Use `SyncTransactionsV2` when complete
account event discovery is required, including recovery of previously untracked consumed public notes. Local-ID lookups
cannot discover an externally submitted transaction whose ID the client does not know.

All synchronization streams are finite. Only an OK end-of-stream completes a result, including an empty result. Stage
all responses and their negative lookup outcomes. Commit one local update only after every stream and proof check
succeeds. Discard partial results after any error and retry the same pinned range. A vault/map/account target can become
unavailable when it leaves the retained account-history window during paging; restart the entire attempt with a newly
authenticated target in that case.

Use `GetLimits` before batching large request lists. Streaming removes aggregate response pagination, while per-message
and request-list limits remain. Transaction messages fit under 4 MiB for the pinned protocol; see
[Transaction Stream Size](./transaction-stream-size.md). The service admits up to 32 finite sync streams globally and
two per client IP across all methods. Missing client IPs share one admission bucket. Compact streams load 256 rows per
page and buffer 32 messages. Transaction streams load and buffer one record. A reader that blocks a producer send for 10
seconds receives `DEADLINE_EXCEEDED`; a disconnected reader releases its permit. These are application buffer limits,
separate from HTTP/2 and proxy buffers.

## Compatibility and deployment

The unary `SyncNotes`, `SyncAccountVault`, `SyncAccountStorageMaps`, `SyncTransactions`, and `SyncNullifiers` endpoints
remain available alongside their streams. Clients can use unary requests when a new method returns `UNIMPLEMENTED`
before any data arrives. Midstream errors and failed proofs must fail the attempt. Do not silently fall back after a
partial response. Keep full account transaction discovery until unknown consumed-public-note recovery has an equivalent
verified discovery source.

Local tests verify exact multi-page results, concurrent block writes, cancellation, admission release, gRPC-Web OK
trailers, and non-OK terminal errors. Client adoption and the deployment proxy path require separate acceptance. Before
removing compatibility support, test native and browser clients through the actual reverse proxy/load balancer: check
stream forwarding without whole-body buffering, cancellation, terminal trailers, idle deadlines, and configured
per-message limits. Verify the server request timeout and the body-stream lifetime separately. Record consumer versions
and owner approval for the removal release. Repository tests do not establish production deployment acceptance.

## Block Streaming

| Method              | Purpose                                                                               |
| ------------------- | ------------------------------------------------------------------------------------- |
| `BlockSubscription` | Streams committed blocks from `block_from`, replaying history before live blocks.     |
| `ProofSubscription` | Streams block proofs from `block_from`, replaying existing proofs before live proofs. |

These subscriptions replicate chain data from an upstream source. They also support indexers and explorers that need an
append-only view of network progress.

## Network Note Debugging

| Method                 | Purpose                                                                                    |
| ---------------------- | ------------------------------------------------------------------------------------------ |
| `GetNetworkNoteStatus` | Returns the lifecycle status of a network note tracked by the network transaction builder. |
