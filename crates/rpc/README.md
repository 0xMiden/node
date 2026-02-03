# Miden node RPC

Contains the code defining the [Miden node's RPC component](/README.md#architecture). This component serves the
user-facing [gRPC](https://grpc.io) methods used to submit transactions and sync with the state of the network.

This is the **only** set of node RPC methods intended to be publicly available.

For more information on the installation and operation of this component, please see the [node's readme](/README.md).

## API overview

The full gRPC method definitions can be found in the [proto](../proto/README.md) crate.

<!--toc:start-->

- [CheckNullifiers](#checknullifiers)
- [SyncNullifiers](#syncnullifiers)
- [GetAccount](#getaccount)
- [GetBlockByNumber](#getblockbynumber)
- [GetBlockHeaderByNumber](#getblockheaderbynumber)
- [GetLimits](#getlimits)
- [GetNotesById](#getnotesbyid)
- [GetNoteScriptByRoot](#getnotescriptbyroot)
- [SubmitProvenTransaction](#submitproventransaction)
- [SyncAccountVault](#SyncAccountVault)
- [SyncNotes](#syncnotes)
- [SyncState](#syncstate)
- [SyncAccountStorageMaps](#syncaccountstoragemaps)
- [SyncTransactions](#synctransactions)

<!--toc:end-->

---

### CheckNullifiers

Returns a nullifier proof for each of the requested nullifiers.

**Limits:** `nullifier` (1000)

#### Error Handling

When nullifier checking fails, detailed error information is provided through gRPC status details. The following error codes may be returned:

| Error Code                | Value | gRPC Status        | Description                           |
|---------------------------|-------|--------------------|---------------------------------------|
| `INTERNAL_ERROR`          | 0     | `INTERNAL`         | Internal server error occurred        |
| `DESERIALIZATION_FAILED`  | 1     | `INVALID_ARGUMENT` | Malformed nullifier format            |
| `TOO_MANY_NULLIFIERS`     | 2     | `INVALID_ARGUMENT` | Too many nullifiers in request        |

---

### GetAccount

Returns an account witness (Merkle proof of inclusion in the account tree) and optionally account details.

The witness proves the account's state commitment in the account tree. If details are requested, the response also includes the account's header, code, vault assets, and storage data. Account details are only available for public accounts.

If `block_num` is provided, returns the state at that historical block; otherwise, returns the latest state.

---

### GetBlockByNumber

Returns raw block data for the specified block number.

---

### GetBlockHeaderByNumber

Retrieves block header by given block number. Optionally, it also returns the MMR path and current chain length to
authenticate the block's inclusion.

---

### GetLimits

Returns the query parameter limits configured for RPC endpoints.

This endpoint allows clients to discover the maximum number of items that can be requested in a single call for
various endpoints. The response contains a map of endpoint names to their parameter limits.

---

### GetNotesById

Returns a list of notes matching the provided note IDs.

**Limits:** `note_id` (100)

#### Error Handling

When note retrieval fails, detailed error information is provided through gRPC status details. The following error codes may be returned:

| Error Code                | Value | gRPC Status        | Description                           |
|---------------------------|-------|--------------------|---------------------------------------|
| `INTERNAL_ERROR`          | 0     | `INTERNAL`         | Internal server error occurred        |
| `DESERIALIZATION_FAILED`  | 1     | `INVALID_ARGUMENT` | Malformed note ID format              |
| `NOTE_NOT_FOUND`          | 2     | `NOT_FOUND`        | One or more note IDs don't exist     |
| `TOO_MANY_NOTE_IDS`       | 3     | `INVALID_ARGUMENT` | Too many note IDs in request          |
| `NOTE_NOT_PUBLIC`         | 4     | `PERMISSION_DENIED`| Note details not publicly accessible  |

---

### GetNoteScriptByRoot

Returns the script for a note by its root.

#### Error Handling

When script retrieval fails, detailed error information is provided through gRPC status details. The following error codes may be returned:

| Error Code                | Value | gRPC Status        | Description                           |
|---------------------------|-------|--------------------|---------------------------------------|
| `INTERNAL_ERROR`          | 0     | `INTERNAL`         | Internal server error occurred        |
| `DESERIALIZATION_FAILED`  | 1     | `INVALID_ARGUMENT` | Malformed script root format          |
| `SCRIPT_NOT_FOUND`        | 2     | `NOT_FOUND`        | Script with given root doesn't exist  |

---

### SubmitProvenTransaction

Submits a proven transaction to the Miden network for inclusion in future blocks. The transaction must be properly formatted and include a valid execution proof.

#### Error Handling

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

**Error Details Serialization**: The `Status.details` field contains a single byte with the numeric error code value. Clients can decode this by reading `details[0]` to get the error code (0-8) and mapping it to the corresponding enum value.

Clients should inspect both the gRPC status code and the detailed error code in the `Status.details` field to determine the appropriate response. For `INTERNAL_ERROR` cases, the detailed error message is replaced with a generic message for security reasons.

---

### SyncNullifiers

Returns nullifier synchronization data for a set of prefixes within a given block range. This method allows
clients to efficiently track nullifier creation by retrieving only the nullifiers produced between two blocks.

**Limits:** `nullifier` (1000)

Caller specifies the `prefix_len` (currently only 16), the list of prefix values (`nullifiers`), and the block
range (`from_start_block`, optional `to_end_block`). The response includes all matching nullifiers created within that
range, the last block included in the response (`block_num`), and the current chain tip (`chain_tip`).

If the response is chunked due to exceeding the maximum returned entries, continue by issuing another request with
consecutive block number to retrieve subsequent updates.

#### Error Handling

When nullifier synchronization fails, detailed error information is provided through gRPC status details. The following error codes may be returned:

| Error Code                | Value | gRPC Status        | Description                           |
|---------------------------|-------|--------------------|---------------------------------------|
| `INTERNAL_ERROR`          | 0     | `INTERNAL`         | Internal server error occurred        |
| `DESERIALIZATION_FAILED`  | 1     | `INVALID_ARGUMENT` | Malformed nullifier prefix format     |
| `INVALID_BLOCK_RANGE`     | 2     | `INVALID_ARGUMENT` | Invalid block range parameters        |
| `INVALID_PREFIX_LENGTH`   | 3     | `INVALID_ARGUMENT` | Unsupported prefix length (only 16)   |
---

### SyncAccountVault

Returns information that allows clients to sync asset values for specific public accounts within a block range.

For any `block_range`, the latest known set of assets is returned for the requested account ID.
The data can be split and a cutoff block may be selected if there are too many assets to sync. The response contains
the chain tip so that the caller knows when it has been reached.

#### Error Handling

When account vault synchronization fails, detailed error information is provided through gRPC status details. The following error codes may be returned:

| Error Code                | Value | gRPC Status        | Description                           |
|---------------------------|-------|--------------------|---------------------------------------|
| `INTERNAL_ERROR`          | 0     | `INTERNAL`         | Internal server error occurred        |
| `DESERIALIZATION_FAILED`  | 1     | `INVALID_ARGUMENT` | Malformed account ID format           |
| `INVALID_BLOCK_RANGE`     | 2     | `INVALID_ARGUMENT` | Invalid block range parameters        |
| `ACCOUNT_NOT_PUBLIC`      | 3     | `INVALID_ARGUMENT` | Account is not public (no vault sync) |

---

### SyncNotes

Returns info which can be used by the client to sync up to the tip of chain for the notes they are interested in.

**Limits:** `note_tag` (1000)

Client specifies the `note_tags` they are interested in, and the block range from which to search for matching notes. The request will then return the next block containing any note matching the provided tags within the specified range.

The response includes each note's metadata and inclusion proof.

A basic note sync can be implemented by repeatedly requesting the previous response's block until reaching the tip of the chain.

#### Error Handling

When note synchronization fails, detailed error information is provided through gRPC status details. The following error codes may be returned:

| Error Code                | Value | gRPC Status        | Description                           |
|---------------------------|-------|--------------------|---------------------------------------|
| `INTERNAL_ERROR`          | 0     | `INTERNAL`         | Internal server error occurred        |
| `DESERIALIZATION_FAILED`  | 1     | `INVALID_ARGUMENT` | Malformed note tags format            |
| `INVALID_BLOCK_RANGE`     | 2     | `INVALID_ARGUMENT` | Invalid block range parameters        |
| `TOO_MANY_TAGS`           | 3     | `INVALID_ARGUMENT` | Too many note tags in request         |

---

### SyncState

Returns info which can be used by the client to sync up to the latest state of the chain for the objects (accounts and
notes) the client is interested in.

**Limits:** `account_id` (1000), `note_tag` (1000)

This request returns the next block containing requested data. It also returns `chain_tip` which is the latest block
number in the chain. Client is expected to repeat these requests in a loop until
`response.block_header.block_num == response.chain_tip`, at which point the client is fully synchronized with the chain.

Each request also returns info about new notes, accounts, etc. created. It also returns Chain MMR delta that can be
used to update the state of Chain MMR. This includes both chain MMR peaks and chain MMR nodes.

For preserving some degree of privacy, note tags contain only high part of hashes. Thus, returned data contains excessive
notes, client can make additional filtering of that data on its side.

---

### SyncAccountStorageMaps

Returns storage map synchronization data for a specified public account within a given block range. This method allows clients to efficiently sync the storage map state of an account by retrieving only the changes that occurred between two blocks.

Caller specifies the `account_id` of the public account and the block range `block_range` for which to retrieve storage updates. The response includes all storage map key-value updates that occurred within that range, along with the last block included in the sync and the current chain tip.

This endpoint enables clients to maintain an updated view of account storage.

#### Error Handling

When storage map synchronization fails, detailed error information is provided through gRPC status details. The following error codes may be returned:

| Error Code                | Value | gRPC Status        | Description                           |
|---------------------------|-------|--------------------|---------------------------------------|
| `INTERNAL_ERROR`          | 0     | `INTERNAL`         | Internal server error occurred        |
| `DESERIALIZATION_FAILED`  | 1     | `INVALID_ARGUMENT` | Malformed account ID format           |
| `INVALID_BLOCK_RANGE`     | 2     | `INVALID_ARGUMENT` | Invalid block range parameters        |
| `ACCOUNT_NOT_FOUND`       | 3     | `NOT_FOUND`        | Account ID does not exist             |
| `ACCOUNT_NOT_PUBLIC`      | 4     | `INVALID_ARGUMENT` | Account storage not publicly accessible |

---

### SyncTransactions

Returns transaction records for specific accounts within a block range.

#### Error Handling

When transaction synchronization fails, detailed error information is provided through gRPC status details. The following error codes may be returned:

| Error Code                | Value | gRPC Status        | Description                           |
|---------------------------|-------|--------------------|---------------------------------------|
| `INTERNAL_ERROR`          | 0     | `INTERNAL`         | Internal server error occurred        |
| `DESERIALIZATION_FAILED`  | 1     | `INVALID_ARGUMENT` | Malformed account ID format           |
| `INVALID_BLOCK_RANGE`     | 2     | `INVALID_ARGUMENT` | Invalid block range parameters        |
| `ACCOUNT_NOT_FOUND`       | 3     | `NOT_FOUND`        | Account ID does not exist             |
| `TOO_MANY_ACCOUNT_IDS`    | 4     | `INVALID_ARGUMENT` | Too many account IDs in request       |

---

## License

This project is [MIT licensed](../../LICENSE).
