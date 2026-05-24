---
title: "Node gRPC Reference"
sidebar_position: 1
---

# gRPC Reference

This is a reference of the Node's public RPC interface. It consists of a gRPC API which may be used to submit transactions and query the state of the blockchain.

The gRPC service definition can be found in the Miden node's `proto` [directory](https://github.com/0xMiden/node/tree/main/proto) in the `rpc.proto` file.

<!--toc:start-->

- [GetAccount](#getaccount)
- [GetBlockByNumber](#getblockbynumber)
- [GetBlockHeaderByNumber](#getblockheaderbynumber)
- [GetLimits](#getlimits)
- [GetNetworkNoteStatus](#getnetworknotestatus)
- [GetNotesById](#getnotesbyid)
- [GetNoteScriptByRoot](#getnotescriptbyroot)
- [BlockSubscription](#blocksubscription)
- [ProofSubscription](#proofsubscription)
- [Status](#status)
- [SubmitProvenTx](#submitproventx)
- [SyncAccountStorageMaps](#syncaccountstoragemaps)
- [SyncAccountVault](#syncaccountvault)
- [SyncChainMmr](#syncchainmmr)
- [SyncNotes](#syncnotes)
- [SyncNullifiers](#syncnullifiers)
- [SyncTransactions](#synctransactions)

<!--toc:end-->

## API Endpoints

### GetAccount

Request an account witness (Merkle proof of inclusion in the account tree) and optionally account details.

The witness proves the account's state commitment in the account tree. If details are requested, the response also includes the account's header, code, vault assets, and storage data. Account details are only available for public accounts.

If `block_num` is provided, returns the state at that historical block; otherwise, returns the latest state.

#### Error Codes

When the request fails, detailed error information is provided through gRPC status details. The following error codes may be returned:

| Error Code                | Value | gRPC Status        | Description                                          |
|---------------------------|-------|--------------------|------------------------------------------------------|
| `INTERNAL_ERROR`          | 0     | `INTERNAL`         | Internal server error occurred                       |
| `DESERIALIZATION_FAILED`  | 1     | `INVALID_ARGUMENT` | Request could not be deserialized                    |
| `ACCOUNT_NOT_FOUND`       | 2     | `INVALID_ARGUMENT` | Account not found at the requested block             |
| `ACCOUNT_NOT_PUBLIC`      | 3     | `INVALID_ARGUMENT` | Account details requested for a non-public account   |
| `UNKNOWN_BLOCK`           | 4     | `INVALID_ARGUMENT` | Requested block number is unknown                    |
| `BLOCK_PRUNED`            | 5     | `INVALID_ARGUMENT` | Requested block has been pruned                      |

### GetBlockByNumber

Request the raw data for a specific block.

### GetBlockHeaderByNumber

Request a specific block header and its inclusion proof.

### GetLimits

Returns the query parameter limits configured for RPC endpoints.

This endpoint allows clients to discover the maximum number of items that can be requested in a single call for various endpoints. The response contains a map of endpoint names to their parameter limits.

**Example response structure:**

```json
{
  "endpoints": {
    "SyncNullifiers": { "parameters": { "nullifier": 1000 } },
    "SyncTransactions": { "parameters": { "account_id": 1000 } },
    "SyncAccountVault": { "parameters": { "account_id": 1000 } },
    "SyncAccountStorageMaps": { "parameters": { "account_id": 1000 } },
    "SyncNotes": { "parameters": { "note_tag": 1000 } },
    "GetNotesById": { "parameters": { "note_id": 100 } }
  }
}
```

### GetNotesById

Request a set of notes.

**Limits:** `note_id` (100)

### GetNetworkNoteStatus

Returns the current lifecycle status of a network note. The status indicates where the note is in its lifecycle: pending execution, processed (consumed by a transaction in the mempool), or discarded after too many failed attempts. The response also includes the latest execution error, if any.

This endpoint is only available when the network transaction builder is enabled and connected. If it is not configured, the endpoint returns `UNAVAILABLE`.

For network notes that perform FPI into another account, `last_error` is the first place to check when the foreign
account cannot be loaded. A missing, private, or not-yet-visible foreign account causes execution to fail in the network
transaction builder. The note remains pending while retries are available, and the same failure is returned in
`last_error` until a later attempt succeeds or the note is discarded.

#### Request

```protobuf
message NoteId {
    Digest id = 1;  // The note ID
}
```

#### Response

```protobuf
enum NetworkNoteStatus {
    NETWORK_NOTE_STATUS_UNSPECIFIED = 0;
    NETWORK_NOTE_STATUS_PENDING = 1;    // Awaiting execution or being retried
    NETWORK_NOTE_STATUS_NULLIFIER_INFLIGHT = 2;  // Consumed by a transaction sent to block producer
    NETWORK_NOTE_STATUS_DISCARDED = 3;  // Exceeded max retries, will not be retried
    NETWORK_NOTE_STATUS_NULLIFIER_COMMITTED = 4;  // Consuming transaction committed on-chain
}

message GetNetworkNoteStatusResponse {
    NetworkNoteStatus status = 1;                // Current lifecycle status
    optional string last_error = 2;              // The latest error message, if any
    uint32 attempt_count = 3;                    // Number of failed execution attempts
    optional fixed32 last_attempt_block_num = 4; // Block number of the last failed attempt, if any
}
```

If the note is not found in the network transaction builder's database, the endpoint returns `NOT_FOUND`.

### GetNoteScriptByRoot

Request the script for a note by its root.

### BlockSubscription

Streams committed blocks starting from `block_from` inclusive.

Each stream item contains the serialized signed block and the committed chain tip observed when
the item was emitted.

### ProofSubscription

Streams block proofs starting from `block_from` inclusive.

Each stream item contains the block number, serialized block proof, and the proven chain tip
observed when the item was emitted.

### Status

Request the status of the node components. The response contains the current version of the RPC component and the connection status of the other components, including their versions and the number of the most recent block in the chain (chain tip).

### SubmitProvenTx

Submit a transaction to the network.

This endpoint accepts a proven transaction and attempts to add it to the mempool for inclusion in future blocks. The transaction must be properly formatted and include a valid execution proof.

#### Error Codes

When transaction submission fails, detailed error information is provided through gRPC status details. The following error codes may be returned:

| Error Code                                    | Value | gRPC Status        | Description                                                   |
|-----------------------------------------------|-------|--------------------|---------------------------------------------------------------|
| `INTERNAL_ERROR`                              | 0     | `INTERNAL`         | Internal server error occurred                                |
| `DESERIALIZATION_FAILED`                      | 1     | `INVALID_ARGUMENT` | Transaction could not be deserialized                         |
| `INVALID_TRANSACTION_PROOF`                   | 2     | `INVALID_ARGUMENT` | Transaction execution proof is invalid                        |
| `INCORRECT_ACCOUNT_INITIAL_COMMITMENT`        | 3     | `INVALID_ARGUMENT` | Account's initial state doesn't match current state           |
| `INPUT_NOTES_ALREADY_CONSUMED`                | 4     | `INVALID_ARGUMENT` | Input notes have already been consumed by another transaction |
| `UNAUTHENTICATED_NOTES_NOT_FOUND`             | 5     | `INVALID_ARGUMENT` | Required unauthenticated notes were not found                 |
| `OUTPUT_NOTES_ALREADY_EXIST`                  | 6     | `INVALID_ARGUMENT` | Output note IDs are already in use                            |
| `TRANSACTION_EXPIRED`                         | 7     | `INVALID_ARGUMENT` | Transaction has exceeded its expiration block height          |

### SyncAccountStorageMaps

Returns storage map synchronization data for a specified public account within a given block range. This method allows clients to efficiently sync the storage map state of an account by retrieving only the changes that occurred between two blocks.

Caller specifies the `account_id` of the public account and the block range (`block_from`, `block_to`) for which to retrieve storage updates. The response includes all storage map key-value updates that occurred within that range, along with the last block included in the sync and the current chain tip.

This endpoint enables clients to maintain an updated view of account storage.

### SyncAccountVault

Returns information that allows clients to sync asset values for specific public accounts within a block range.

For any `[block_from..block_to]` range, the latest known set of assets is returned for the requested account ID. The data can be split and a cutoff block may be selected if there are too many assets to sync. The response contains the chain tip so that the caller knows when it has been reached.

### SyncChainMmr

Returns MMR delta information needed to synchronize the chain MMR within a block range.

Caller specifies the `block_range`, starting from the last block already represented in its local MMR. The response contains the MMR delta for the requested range, but at most to (including) the chain tip.

### SyncNotes

Iteratively sync data for a given set of note tags.

Client specifies the `note_tags` they are interested in, and the block range from which to search for matching notes. The request will then return the next block containing any note matching the provided tags within the specified range.

The response includes each note's metadata and inclusion proof.

A basic note sync can be implemented by repeatedly requesting the previous response's block until reaching the tip of the chain.

**Limits:** `note_tag` (1000)

### SyncNullifiers

Returns nullifier synchronization data for a set of prefixes within a given block range. This method allows clients to efficiently track nullifier creation by retrieving only the nullifiers produced between two blocks.

Caller specifies the `prefix_len` (currently only 16), the list of prefix values (`nullifiers`), and the block range (`block_from`, optional `block_to`). The response includes all matching nullifiers created within that range, the last block included in the response (`block_num`), and the current chain tip (`chain_tip`).

If the response is chunked (i.e., `block_num < block_to`), continue by issuing another request with `block_from = block_num + 1` to retrieve subsequent updates.

**Limits:** `nullifier` (1000)

### SyncTransactions

Returns transaction records for specific accounts within a block range.

## Error Handling

The Miden node uses standard gRPC error reporting mechanisms. When an RPC call fails, a `Status` object is returned containing:

- **Status Code**: Standard gRPC status codes (`INVALID_ARGUMENT`, `INTERNAL`, etc.).
- **Message**: Human-readable error description.
- **Details**: Additional structured error information (when available).

For critical operations like transaction submission, detailed error codes are provided in the `Status.details` field to help clients understand the specific failure reason and take appropriate action.

### Error Details Format

The `Status.details` field contains the specific error code serialized as raw bytes:

- **Format**: Single byte containing the numeric error code value
- **Decoding**: Read the first byte to get the error code
- **Mapping**: Map the numeric value to the corresponding error enum

**Example decoding** (pseudocode):

```
if status.details.length > 0:
    error_code = status.details[0]  // Extract first byte
    switch error_code:
        case 1: return "INTERNAL_ERROR"
        case 2: return "DESERIALIZATION_FAILED"
        case 5: return "INPUT_NOTES_ALREADY_CONSUMED"
        // ... etc
```
