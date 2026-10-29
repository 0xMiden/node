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

## Tracing targets

RPC handlers, subscriptions, and server lifecycle events use `miden::rpc::server`. The shared gRPC request layer uses
the same target for request spans and failure events on both public and internal servers. The funding client uses
`miden::rpc::client`, as do the shared gRPC client connection diagnostics in the proto crate.

Use `MIDEN_STDOUT_FILTER=info,miden::rpc::server=debug` to include debug-level server diagnostics, or select
`miden::rpc::client=debug` for client diagnostics. `MIDEN_OTEL_FILTER` controls OpenTelemetry export; both settings fall
back to `RUST_LOG` when unset. The previous `miden-rpc` and `user::miden-rpc` targets no longer select this crate's
diagnostics, and the default `user=debug` directive no longer enables its debug events.

## License

This project is [MIT licensed](../../LICENSE).
