# Miden node proto

This crate contains protobuf bindings for the APIs exposed by the components of the Miden node and domain types.

> [!WARNING]
> This crate is intended for internal use only. For gRPC bindings please see the [miden-node-proto-build](../../proto/README.md) crate.\
> This crate does not support TLS and cannot be used as a client for the official RPC endpoints.

## Error handling

The node's gRPC endpoints return rich error information using gRPC status details. Each component exposes its own set of error codes which are included in the response details.

Error conversion helpers are defined in `src/errors/mod.rs`. Component-specific gRPC error
details are derived next to the component errors that need to cross a gRPC boundary.

## License
This project is [MIT licensed](../../LICENSE).
