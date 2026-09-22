# RPC Component

This is by far the simplest component. Essentially this is a thin gRPC server which proxies all requests to the store
and block-producer components.

Its main function is to pre-validate all requests before sending them on. This means malformed or non-sensical requests
get rejected _before_ reaching the store and block-producer, reducing their load. Notably this also includes verifying
the proofs of submitting transactions. This allows the block-producer to skip proof verification (it trusts the RPC
component), reducing the load in this critical component.

## RPC Versioning and the HTTP `ACCEPT` header

The RPC component allows clients to negotiate their desired Miden RPC version using the well-known HTTP `ACCEPT` header, using the following format:

```sh
application/vnd.miden; version=<version-req>; genesis=<genesis-commitment>
```

The `version` lets the client specify their supported version and the server will attempt to comply if it can. At this early stage, only client versions which are semver compatible with the
server version are likely to be accepted i.e. the server in all likely only supports a _single version_.

The `genesis` property is intended to let the client confirm they are on the correct network, by specifying the network's genesis commitment. This guards against operating on the wrong network,
as well as against network resets.

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

The RPC boundary maps errors to gRPC status codes and method-specific detail bytes. The first byte of `Status.details`
identifies the application error. These values are part of the client API and must remain stable.

The read and sync handlers use explicit codes from `crates/rpc/src/server/api/error_codes.rs`. The mempool uses the
`GrpcError` derive macro. This macro assigns codes in variant order and maps internal errors to code `0`. Add new
client-error variants at the end of the mempool error enum to preserve existing codes.

Clients must also accept statuses without details and unknown detail codes.
