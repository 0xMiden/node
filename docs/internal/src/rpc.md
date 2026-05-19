# RPC Component

This is by far the simplest component. Essentially this is a thin gRPC server which proxies all requests to the store
and block-producer components.

Its main function is to pre-validate all requests before sending them on. This means malformed or non-sensical requests
get rejected _before_ reaching the store and block-producer, reducing their load. Notably this also includes verifying
the proofs of submitting transactions. This allows the block-producer to skip proof verification (it trusts the RPC
component), reducing the load in this critical component.

## RPC Versioning

The RPC server enforces version requirements against connecting clients that provide the HTTP ACCEPT header. When this header is provided, its corresponding value must follow this format: `application/vnd.miden.0.9.0+grpc`.

If there is a mismatch in version, clients will encounter an error while executing gRPC requests against the RPC server with the following details:

- gRPC status code: 3 (Invalid Argument)
- gRPC message: Missing required ACCEPT header

The server will reject any version that does not have the same major and minor version to it. This behaviour will change after v1.0.0., at which point only the major version will be taken into account.

## Query limits (`GetLimits`)

The RPC service exposes a `GetLimits` endpoint which returns the query parameter limits enforced by the server for
multi-value parameters (e.g. number of nullifiers, note tags, note IDs, account IDs).

These limits are defined centrally in `miden_node_utils::limiter` and are enforced at the RPC boundary (and also inside
the store) to keep database queries bounded and to keep response payloads within the ~4 MB budget.

`GENERAL_REQUEST_LIMIT` is currently `1000`, and endpoint-specific limits are:

| Endpoint           | Parameter          | Limit  | Rationale                                                            |
| ------------------ | ------------------ | ------ | -------------------------------------------------------------------- |
| `GetAccount`       | `storage_map_key`  | `64`   | SMT proof generation for storage map keys is comparatively expensive |
| `GetNotesById`     | `note_id`          | `100`  | Notes can be large (~32 KiB), so this is intentionally tighter       |
| `SyncNotes`        | `note_tag`         | `1000` | Keeps note sync responses within payload budget                      |
| `SyncNullifiers`   | `nullifier_prefix` | `1000` | Bounds prefix-based nullifier scans                                  |
| `SyncTransactions` | `account_id`       | `1000` | Bounds account filter fan-out and response size                      |

Additional internal-only limits in `miden_node_utils::limiter` (not surfaced by `GetLimits`) include:

| Parameter         | Limit  | Used by                                |
| ----------------- | ------ | -------------------------------------- |
| `note_commitment` | `1000` | Internal note proof lookups            |
| `block_header`    | `1000` | Internal batch/block header operations |

## Error Handling

The RPC component uses domain-specific error enums for structured error reporting instead of proto-generated error types. This provides better control over error codes and makes error handling more maintainable.

### Error Architecture

Error handling follows this pattern:

1. **Domain Errors**: Business logic errors are defined in domain-specific enums
2. **gRPC Conversion**: Domain errors are converted to gRPC `Status` objects with structured details
3. **Error Details**: Specific error codes are embedded in `Status.details` as single bytes

### SubmitProvenTx Errors

Transaction submission errors are:

```rust
enum SubmitProvenTxGrpcError {
    Internal = 0,
    DeserializationFailed = 1,
    InvalidTransactionProof = 2,
    IncorrectAccountInitialCommitment = 3,
    InputNotesAlreadyConsumed = 4,
    UnauthenticatedNotesNotFound = 5,
    OutputNotesAlreadyExist = 6,
    TransactionExpired = 7,
}
```

Error codes are embedded as single bytes in `Status.details`
