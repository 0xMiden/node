# Proto Files Organization

These protobuf files are part of the [Miden node](https://github.com/0xMiden/node#readme) repository.

The root directory contains the public RPC, remote prover, and note transport protocols. The `types` directory contains
node-owned messages for service workflows. The `internal` directory contains the internal component protocols.

Canonical protocol objects come from `miden-objects`. Do not copy these object schemas into this directory. The build
resolves canonical imports through `miden_objects::FILE_DESCRIPTOR_SET`. It includes imported schemas in each exported
service descriptor set. The raw files in this directory alone are not sufficient to generate bindings.

The organization of the files is as follows:

```text
rpc.proto
remote_prover.proto
note_transport.proto
types/
├── submission.proto
└── block_proving.proto
internal/
├── ntx_builder.proto
├── sequencer.proto
└── validator.proto
```

Public service files can import shared node-owned types and canonical object schemas. They must not import internal
service files. This keeps internal services out of public service reflection.

Keep service-specific wrappers with their service. For example, `rpc.proto` owns note query and compact note sync
messages. `internal/validator.proto` owns the signing request and signature response. Submission envelopes belong in
`types/submission.proto`. Block proving requests belong in `types/block_proving.proto`.

See the [migration guidance](../README.md#canonical-protobuf-migration) before updating an existing client.
