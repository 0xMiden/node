---
title: "Public RPC"
sidebar_position: 1
---

# Public RPC

This page summarizes the public gRPC services `miden.node.v1.NodeService` and `miden.node.v2.NodeService`.

As a reminder, you can inspect the exact schema on any deployed network using gRPC reflection:

```bash
grpcurl rpc.testnet.miden.io:443 describe miden.node.v1.NodeService
grpcurl rpc.testnet.miden.io:443 describe miden.node.v2.NodeService
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

The v1 method `RegisterAccount` binds an invitation code to an account ID. Send the original code string in
`invitation_code` and the target account in `account_id`. Codes are case-sensitive. Send the code exactly as received,
without trimming or normalization. Registration does not create an account on chain.

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

`IsInvitationCodeValid` returns `true` if the invitation code can be used to register an account. The code must be
registered in the invitation registry and unused. Send the code in `invitation_code`. This check does not consume the
code.

If the code has already been used, the response returns `false` and sets `account_id` to the registered account. If that
is your account, registration is complete and retrying `RegisterAccount` with the same code succeeds. The field is
omitted for unused or unknown codes.

When account allowlist enforcement is disabled, this method always returns `true`. With enforcement enabled, an empty
code is rejected with `INVALID_ARGUMENT`. Full nodes forward this query to the sequencer.

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

Legacy clients may also include a `version` parameter. The server ignores its value:

```text
application/vnd.miden; version=<semver>; genesis=<genesis-commitment>
```

See [Errors and Limits](./errors-and-limits.md#transaction-submission-errors) for the transaction submission detail
codes returned in gRPC status details.

## State Synchronization

Call `SyncChainMmr` on v2. Omit `target_block_num` to select the committed or proven tip, or supply a block number at or
below that tip. Zero selects genesis. Authenticate the `SyncChainMmr` target header and its MMR delta first. Keep its
block number `N` fixed within each request, and reconcile all results to one common target before committing
synchronization. Delta streams take `StateDeltaRange`: `from_block_exclusive = C` and `to_block_inclusive = N` request
`(C, N]`. Omit the lower bound to include genesis during bootstrap. The target is required. Equal bounds return an empty
delta after target validation.

| Method                   | Purpose                                                                           |
| ------------------------ | --------------------------------------------------------------------------------- |
| `SyncNotes`              | Streams block frames and compact matching notes with target-anchored block paths. |
| `SyncAccountVault`       | Streams the final target value of every changed vault key.                        |
| `SyncAccountStorageMaps` | Streams the final target value of every changed storage-map key.                  |

Vault, storage-map, and nullifier stream items report the block of their last update in `last_updated_at`. This is a
block number, not a timestamp or the authenticated target.

`SyncNotes` sends a block frame exactly once before that block's notes. Reject notes before a block frame,
repeated/backward block frames, and note proofs for another block. Verify each note path against its block's note root
and each block path against the MMR with `N + 1` leaves, including the authenticated target header. Fetch public note
bodies and missing attachment content with `GetNotesById`. Reject malformed or incomplete records.

All synchronization streams are finite. Only an OK end-of-stream completes a result, including an empty result. Stage
all responses and their negative lookup outcomes. Commit one local update only after every required stream and proof
check succeeds at the common target. A terminal error never establishes an empty suffix or a negative lookup result.
Vault and storage-map scans can preserve progress using [block-level resumption](#resuming-vault-and-storage-map-scans).
Other incomplete streams must be retried in full under their existing contracts.

Use `GetLimits` before batching large request lists. Streaming removes aggregate response pagination, while per-message
and request-list limits remain.

The following paginated unary methods are available on v1. Each returns as much of the requested block range as fits in
one response, and the caller repeats the request for the remainder.

| Method                   | Purpose                                                                                 |
| ------------------------ | --------------------------------------------------------------------------------------- |
| `SyncTransactions`       | Returns transaction records for specified accounts within a block range.                |
| `SyncNotes`              | Returns note metadata and inclusion proofs for matching note tags within a block range. |
| `SyncNullifiers`         | Returns nullifiers matching specified 16-bit prefixes within a block range.             |
| `SyncAccountVault`       | Returns public account vault updates within a block range.                              |
| `SyncAccountStorageMaps` | Returns public account storage map updates within a block range.                        |

### Resuming vault and storage-map scans

Block-level resumption lets a client retain downloaded account data when a connection fails or its target leaves
retained history. It uses the existing range fields; the server keeps no synchronization session. This procedure applies
to `SyncAccountVault` and `SyncAccountStorageMaps` only.

Both streams send absolute replacement values in non-decreasing `last_updated_at` order. All values for one update block
arrive before values for a later block, even across internal database pages. Do not depend on the order of keys within a
block. Apply vault removals and zero map values as deletions, rather than adding or subtracting quantities.

Keep the last committed account state separate from staging. Maintain an independent scan checkpoint `P` for each
account's vault and storage-map stream, plus a buffer for the current block. Initially, `P` is the last synchronized
block, or absent for bootstrap. A checkpoint records completed traversal: because values are squashed at the target, the
staged prefix need not be a valid account state at `P`.

1. Authenticate target `N` and request `(P, N]`. Keep `N` fixed for that request. Decode and validate each response,
   rejecting decreasing update blocks or blocks outside the requested range.
2. Buffer values for the current block. When the first value from a later block `B` arrives, apply the preceding block's
   buffer to staging and advance `P` to `B - 1`. Start a new buffer for `B`. The first response also establishes that
   the requested prefix before its block has no matching values. If persisting progress, save staging and its checkpoint
   atomically; the server does not persist them for the client.
3. On a connection interruption, stalled-reader timeout, or unavailable-history error, discard the incomplete block
   buffer and retain the completed staged prefix. Retry `(P, N]` while `N` remains available, or authenticate a newer
   target `M` on the same chain and request `(P, M]`. Never regress the target. If no response arrived, retain the
   previous checkpoint.
4. Only on OK end-of-stream, apply the final buffer and mark this stream complete through its requested target,
   including any empty suffix. An empty successful stream likewise completes through that target.

For example, after receiving update blocks `40, 40, 43, 43` and then an error, resume with `from_block_exclusive = 42`
and the chosen `to_block_inclusive`. This repeats all of block `43`; setting the lower bound to `43` could skip its
remaining values. If the interrupted block is genesis, omit `from_block_exclusive`.

When a previously downloaded key changes after `N`, its replacement or deletion appears at a later update block and is
included in the resumed scan toward `M`. An unchanged completed prefix needs no retransmission. Keep that prefix in
staging until final verification; it is not independently authenticated by the checkpoint.

Before publishing the synchronization update, bring each required stream to the same authenticated target. A vault or
map scan already completed at `N` can catch up with `(N, M]`. Refresh account details at the final target. Use these
details to reconcile storage-slot changes, including removed slots, and verify the reconstructed vault, storage and
account commitments. Commit the account state and global synchronization height only after the other required
synchronization work also completes.

Malformed records, decreasing order, an incompatible chain, or a failed final commitment check invalidate the staging
attempt. Correct invalid requests before retrying, and investigate internal failures rather than automatically moving
the checkpoint. Identify unavailable history by `INVALID_ARGUMENT` with detail code `4` for these endpoints, not by
matching error text; see [stream errors](./errors-and-limits.md#finite-synchronization-stream-errors).

Resumption makes progress between blocks, not within a block. A block whose values cannot be downloaded within the
usable account-history window may be replayed repeatedly. The window is currently 50 blocks, approximately 100–150
seconds at 2–3 seconds per block, with less time for a target already behind the tip. Continuously changing accounts
also require enough client throughput to catch up. Fetching retention-sensitive account data early reduces this risk;
local verification and the final commit may finish after the target has left retention if all required data was
successfully acquired.

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
