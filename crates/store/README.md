# Miden node store

Contains the code defining the [Miden node's store component](/README.md#architecture). This component stores the
network's state and acts as the networks source of truth. It serves a [gRPC](https://grpc.io) API which allow the other
node components to interact with the store. This API is **internal** only and is considered trusted i.e. the node
operator must take care that the store's API endpoint is **only** exposed to the other node components.

For more information on the installation and operation of this component, please see the [node's readme](/README.md).

## RocksDB Feature

The `rocksdb` feature (enabled by default) provides disk-backed storage via RocksDB for `LargeSmt`. Building _requires_ LLVM/Clang for `bindgen`.

### Using System Libraries

To avoid compiling RocksDB from source and safe yourself some time, use system libraries:

```bash
# Install system RocksDB
# (Ubuntu/Debian)
#sudo apt-get install librocksdb-dev clang llvm-dev libclang-dev
# (Fedora)
#sudo dnf install rocksdb rocksdb-devel llvm19 clang19

# Set environment variables to use system library
export ROCKSDB_LIB_DIR=/usr/lib
export ROCKSDB_INCLUDE_DIR=/usr/include
# export ROCKSDB_STATIC=1 (optional)
# (Ubuntu/Debian)
#export LIBCLANG_PATH=/usr/lib/llvm-14/lib
# (Fedora)
#export LIBCLANG_PATH=/usr/lib64/llvm19/lib
```

### Building from Source

Without the environment variables above, `librocksdb-sys` compiles RocksDB from source, which requires a C/C++ toolchain.

## API overview

The full gRPC API can be found [here](../../proto/proto/store.proto).

<!--toc:start-->
- [ApplyBlock](#applyblock)
- [CheckNullifiers](#checknullifiers)
- [GetAccount](#getaccount)
- [GetBlockByNumber](#getblockbynumber)
- [GetBlockHeaderByNumber](#getblockheaderbynumber)
- [GetBlockInputs](#getblockinputs)
- [GetNoteAuthenticationInfo](#getnoteauthenticationinfo)
- [GetNotesById](#getnotesbyid)
- [GetTransactionInputs](#gettransactioninputs)
- [GetNoteScriptByRoot](#getnotescriptbyroot)
- [SyncNullifiers](#syncnullifiers)
- [SyncAccountVault](#syncaccountvault)
- [SyncNotes](#syncnotes)
- [SyncState](#syncstate)
- [SyncAccountStorageMaps](#syncaccountstoragemaps)
- [SyncTransactions](#synctransactions)
<!--toc:end-->

---

### ApplyBlock

Applies changes of a new block to the DB and in-memory data structures. Raw block data is also stored as a flat file.

---

### CheckNullifiers

Returns a nullifier proof for each of the requested nullifiers.

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

### GetBlockInputs

Used by the `block-producer` to query state required to prove the next block.

---

### GetNoteAuthenticationInfo

Returns a list of Note inclusion proofs for the specified Note IDs.

This is used by the `block-producer` as part of the batch proving process.

---

### GetNotesById

Returns a list of notes matching the provided note IDs.

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

### GetTransactionInputs

Used by the `block-producer` to query state required to verify a submitted transaction.

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

### SyncNullifiers

Returns nullifier synchronization data for a set of prefixes within a given block range. This method allows clients to efficiently track nullifier creation by retrieving only the nullifiers produced within a specific range of blocks.

Caller specifies the `prefix_len` (currently only 16), the list of prefix values (`nullifiers`), and the block
range (`block_from`, optional `block_to`). The response includes all matching nullifiers created within that
range, the last block included in the response (`resp.block_num`), and the current chain tip (`chain_tip`).

If the response is chunked (i.e., `resp.block_num < block_to`), continue by issuing another request with
`block_from = block_num + 1` to retrieve subsequent updates.

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

Returns info which can be used by the client to sync up to the latest state of the chain for the objects (accounts,
notes, nullifiers) the client is interested in.

This request returns the next block containing requested data. It also returns `chain_tip` which is the latest block
number in the chain. Client is expected to repeat these requests in a loop until
`response.block_header.block_num == response.chain_tip`, at which point the client is fully synchronized with the chain.

Each request also returns info about new notes, nullifiers etc. created. It also returns Chain MMR delta that can be
used to update the state of Chain MMR. This includes both chain MMR peaks and chain MMR nodes.

For preserving some degree of privacy, note tags and nullifiers filters contain only high part of hashes. Thus, returned
data contains excessive notes and nullifiers, client can make additional filtering of that data on its side.

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
