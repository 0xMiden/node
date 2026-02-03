---
title: "Node gRPC Reference"
sidebar_position: 1
---

# gRPC Reference

This is a reference of the Node's public RPC interface. It consists of a gRPC API which may be used to submit transactions and query the state of the blockchain.

The gRPC service definition can be found in the Miden node's `proto` [directory](https://github.com/0xMiden/miden-node/tree/main/proto) in the `rpc.proto` file.

<!--toc:start-->

- [CheckNullifiers](#checknullifiers)
- [GetAccount](#getaccount)
- [GetBlockByNumber](#getblockbynumber)
- [GetBlockHeaderByNumber](#getblockheaderbynumber)
- [GetLimits](#getlimits)
- [GetNotesById](#getnotesbyid)
- [GetNoteScriptByRoot](#getnotescriptbyroot)
- [SubmitProvenTransaction](#submitproventransaction)
- [SyncNullifiers](#syncnullifiers)
- [SyncAccountVault](#syncaccountvault)
- [SyncNotes](#syncnotes)
- [SyncState](#syncstate)
- [SyncAccountStorageMaps](#syncaccountstoragemaps)
- [SyncTransactions](#synctransactions)
- [Status](#status)

<!--toc:end-->

## API Endpoints

### CheckNullifiers

Request Sparse Merkle Tree opening proofs to verify whether nullifiers have been consumed.

#### Request

```protobuf
message NullifierList {
    repeated Digest nullifiers = 1;  // List of nullifiers to check
}
```

#### Response

```protobuf
message CheckNullifiersResponse {
    repeated SmtOpening proofs = 1;  // One proof per requested nullifier
}

message SmtOpening {
    SparseMerklePath path = 1;  // Merkle authentication path
    SmtLeaf leaf = 2;           // Leaf at this position
}

message SmtLeaf {
    oneof leaf {
        uint64 empty_leaf_index = 1;
        SmtLeafEntry single = 2;
        SmtLeafEntryList multiple = 3;
    }
}
```

#### Understanding Proofs

**Non-Inclusion (Nullifier NOT consumed):**
- `leaf` contains `empty_leaf_index`
- Note can still be consumed

**Inclusion (Nullifier IS consumed):**
- `leaf` contains `single` or `multiple` with key-value pairs, including the `nullifier` key
- Note has been spent

#### Verification

```rust
use miden_crypto::merkle::{SmtProof, SmtProofError};

let block_header = get_latest_block_header();
let nullifier_tree_root = block_header.state_commitment().nullifier_root();

let proof: SmtProof = smt_opening.try_into()?;

match proof.verify_unset(&nullifier, &nullifier_tree_root) {
    Ok(()) => {
        // Nullifier is NOT in the tree - note can be consumed
    }
    Err(SmtProofError::ValueMismatch { .. }) => {
        // Proof is valid, but nullifier has a value (not empty) - note already consumed
    }
    Err(_) => {
        // Proof is invalid (wrong root, wrong key, etc.)
    }
}
```

**Limits:** `nullifier` (1000)

### GetAccount

Request an account witness (Merkle proof of inclusion in the account tree) and optionally account details.

The witness proves the account's state commitment in the account tree. If details are requested, the response also includes the account's header, code, vault assets, and storage data. Account details are only available for public accounts.

If `block_num` is provided, returns the state at that historical block; otherwise, returns the latest state.

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
    "CheckNullifiers": { "parameters": { "nullifier": 1000 } },
    "SyncNullifiers": { "parameters": { "nullifier": 1000 } },
    "SyncState": { "parameters": { "account_id": 1000, "note_tag": 1000 } },
    "SyncNotes": { "parameters": { "note_tag": 1000 } },
    "GetNotesById": { "parameters": { "note_id": 100 } }
  }
}
```

### GetNotesById

Request a set of notes.

**Limits:** `note_id` (100)

### GetNoteScriptByRoot

Request the script for a note by its root.

### SubmitProvenTransaction

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

### SyncNullifiers

Returns nullifier synchronization data for a set of prefixes within a given block range. This method allows clients to efficiently track nullifier creation by retrieving only the nullifiers produced between two blocks.

Caller specifies the `prefix_len` (currently only 16), the list of prefix values (`nullifiers`), and the block range (`block_from`, optional `block_to`). The response includes all matching nullifiers created within that range, the last block included in the response (`block_num`), and the current chain tip (`chain_tip`).

If the response is chunked (i.e., `block_num < block_to`), continue by issuing another request with `block_from = block_num + 1` to retrieve subsequent updates.

**Limits:** `nullifier` (1000)

### SyncAccountVault

Returns information that allows clients to sync asset values for specific public accounts within a block range.

For any `[block_from..block_to]` range, the latest known set of assets is returned for the requested account ID. The data can be split and a cutoff block may be selected if there are too many assets to sync. The response contains the chain tip so that the caller knows when it has been reached.

### SyncNotes

Iteratively sync data for a given set of note tags.

Client specifies the `note_tags` they are interested in, and the block range from which to search for matching notes. The request will then return the next block containing any note matching the provided tags within the specified range.

The response includes each note's metadata and inclusion proof.

A basic note sync can be implemented by repeatedly requesting the previous response's block until reaching the tip of the chain.

**Limits:** `note_tag` (1000)

### SyncState

Iteratively sync data for specific notes and accounts.

This request returns the next block containing data of interest. Client is expected to repeat these requests in a loop until the response reaches the head of the chain, at which point the data is fully synced.

Each update response also contains info about new notes, accounts etc. created. It also returns Chain MMR delta that can be used to update the state of Chain MMR. This includes both chain MMR peaks and chain MMR nodes.

The low part of note tags are redacted to preserve some degree of privacy. Returned data therefore contains additional notes which should be filtered out by the client.

**Limits:** `account_id` (1000), `note_tag` (1000)

### SyncAccountStorageMaps

Returns storage map synchronization data for a specified public account within a given block range. This method allows clients to efficiently sync the storage map state of an account by retrieving only the changes that occurred between two blocks.

Caller specifies the `account_id` of the public account and the block range (`block_from`, `block_to`) for which to retrieve storage updates. The response includes all storage map key-value updates that occurred within that range, along with the last block included in the sync and the current chain tip.

This endpoint enables clients to maintain an updated view of account storage.

### SyncTransactions

Returns transaction records for specific accounts within a block range.

### Status

Request the status of the node components. The response contains the current version of the RPC component and the connection status of the other components, including their versions and the number of the most recent block in the chain (chain tip).

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
