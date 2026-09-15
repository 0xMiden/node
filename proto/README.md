# Miden node proto build

`proto-build` exposes protobuf `FileDescriptorSet` values for the public Miden node APIs. It is part of the
[Miden node](https://github.com/0xMiden/node#readme) repository.

## Role

This crate is intended for projects that need to generate gRPC bindings from the same protobuf API definitions used by
the node. It includes descriptors for the public RPC API and remote prover API, and an optional feature for internal
component APIs used by the Miden node workspace.

Each descriptor set includes its imported schemas. External clients can use these self-contained descriptors to generate
bindings in other languages. Canonical object schemas come from the published `miden-objects` crate through its
`FILE_DESCRIPTOR_SET`. The raw node protobuf files in this repository do not contain all imported schemas. Clients that
compile raw files must also supply the canonical schemas from the matching `miden-objects` release.

For project navigation and documentation links, see the [primary README](https://github.com/0xMiden/node#readme).

## Crate Features

- `internal`: exposes file descriptors for internal node component APIs. These APIs are not intended for general client
  use.

## License

This project is [MIT licensed](../LICENSE).
