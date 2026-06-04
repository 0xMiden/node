# grpc-error-macro

`grpc-error-macro` is a procedural macro used by the Miden node workspace to derive gRPC error mapping boilerplate. It
is part of the [Miden node](https://github.com/0xMiden/node#readme) repository.

## Role

The macro derives the node's internal `GrpcError` integration for error enums that cross gRPC boundaries. It generates a
compact wire-facing error enum, maps implementation errors to API error codes, and supports marking selected variants as
internal errors.

This is an implementation detail for the node crates. External users should normally interact with the public protobuf
API and documented gRPC status behavior rather than depend on this macro directly.

## License

This project is [MIT licensed](../../LICENSE).
