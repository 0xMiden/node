# Miden node RPC

`rpc` contains the public RPC server implementation used by the Miden node. It is part of the
[Miden node](https://github.com/0xMiden/node#readme) workspace and is embedded by the `node` binary rather than operated
directly.

## Role

The RPC component is the public client-facing boundary for a node. It serves gRPC methods for chain state queries,
synchronization, transaction submission, status, and related client workflows.

The component validates and normalizes public requests before forwarding work to the store, block-producer, validator,
or network transaction builder as appropriate. It is the only node component intended to be exposed to clients.

## API Definitions

The protobuf API definition is published through `proto-build`. For project navigation and documentation links, see the
[primary README](https://github.com/0xMiden/node#readme).

## License

This project is [MIT licensed](../../LICENSE).
