# Miden node proto

`proto` contains generated protobuf bindings, conversion code, and gRPC error helpers used inside the Miden node
workspace. It is part of the [Miden node](https://github.com/0xMiden/node#readme) repository.

## Role

This crate is an internal implementation crate for the node binaries and component crates. It is not the recommended
crate for external clients that want to generate bindings from the public protobuf API.

For external gRPC client generation, use `proto-build`.

## Notes

This crate does not provide a ready-to-use TLS client for official public RPC endpoints. Client applications should
configure transport security in their generated client stack.

## License

This project is [MIT licensed](../../LICENSE).
