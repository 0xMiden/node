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

## Error Handling

The RPC component uses domain-specific error enums for structured error reporting instead of proto-generated error types. This provides better control over error codes and makes error handling more maintainable.

### Error Architecture

Error handling follows this pattern:

1. **Domain Errors**: Business logic errors are defined in domain-specific enums
2. **gRPC Conversion**: Domain errors are converted to gRPC `Status` objects with structured details
3. **Error Details**: Specific error codes are embedded in `Status.details` as single bytes
