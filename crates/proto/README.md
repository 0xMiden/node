# Miden node proto

`proto` contains generated protobuf bindings, conversion code, and gRPC error helpers used inside the Miden node
workspace. It is part of the [Miden node](https://github.com/0xMiden/node#readme) repository.

## Role

This crate is an internal implementation crate for the node binaries and component crates. It is not the recommended
crate for external clients that want to generate bindings from the public protobuf API.

For external gRPC client generation, use `proto-build`.

## Decoding

Node messages use `miden-protobuf` to generate decoded records. Use `decode_and_verify()` to check field
representations, required fields, and domain invariants. Use `decode_and_verify_with(context)` when verification needs
external context. Use `decode_and_build_unchecked()` only when the caller can enforce the checks that the implementation
documents.

Use `decode_fields()` separately when the caller needs decoded fields or typed domain errors. Then call `verify()`,
`verify_with()`, or `build_unchecked()` as required. The combined helpers retain the conversion stage and original
error.

Registration uses a handwritten decoder to keep invitation codes out of `Debug` output.

Message fields are required unless the schema marks them `optional`. A `oneof` is required unless the build
configuration marks it optional. The account detail request permits an absent storage request. Decoded oneofs provide
`into_<variant>()` accessors that report a conversion error when the variant does not match.

Optional, repeated, and map fields use `OptionalField`, `RepeatedField`, and `MapField` wrappers. Their conversion
methods retain the field name and the element index or map key on failure. Set conversion requires an explicit duplicate
policy. The RPC limit maps use generated map decoding.

Conversion errors retain the field path and source. Use `ConversionError::into_status` at gRPC boundaries to return
`INVALID_ARGUMENT`.

## Notes

This crate does not provide a ready-to-use TLS client for official public RPC endpoints. Client applications should
configure transport security in their generated client stack.

## License

This project is [MIT licensed](../../LICENSE).
