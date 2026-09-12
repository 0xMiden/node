# Miden node proto

`proto` contains generated protobuf bindings, conversion code, and gRPC error helpers used inside the Miden node
workspace. It is part of the [Miden node](https://github.com/0xMiden/node#readme) repository.

## Role

This crate is an internal implementation crate for the node binaries and component crates. It is not the recommended
crate for external clients that want to generate bindings from the public protobuf API.

For external gRPC client generation, use `proto-build`.

## Decoding

Node messages use `miden-protobuf` to generate decoded records. Call `decode_fields()` to check field representations
and required fields. Then call `verify()` to check domain invariants. Use `verify_with()` when verification needs
external context. Use `build_unchecked()` only when the caller can enforce the checks that the implementation documents.

Message fields are required unless the schema marks them `optional`. Oneofs are required unless the build configuration
marks them optional. The account detail request permits an absent storage request. The RPC limit maps use atomic
adapters because the derive does not support map fields.

Conversion errors retain the field path and source. Use `errors::conversion_error_to_status` at gRPC boundaries to
return `INVALID_ARGUMENT`.

## Notes

This crate does not provide a ready-to-use TLS client for official public RPC endpoints. Client applications should
configure transport security in their generated client stack.

## License

This project is [MIT licensed](../../LICENSE).
