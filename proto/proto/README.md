# Proto Files Organization

The files are organized by a visibility hierarchy, where the root directory contains the public-facing RPC and remote prover protocols, while the `types` directory contains the data types used by these protocols. The `internal` directory contains the internal protocols used by the node, such as non-transactional data and validator protocols.

The organization of the files is as follows:

```
rpc.proto
remote_prover.proto
types/
├── primitives.proto
└── xxx.proto
internal/
├── ntx_builder.proto
└── validator.proto
```

The public-facing files should only allow the usage of the `types` directory, to avoid service reflection to internal protocols.
