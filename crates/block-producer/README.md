# Miden node block producer

`block-producer` contains the block sequencing and block syncing implementation used by the Miden node. It is part of
the [Miden node](https://github.com/0xMiden/node#readme) workspace and is embedded by the `node` binary rather than
operated directly.

## Operation Modes

### Sequencer

When `node` runs in sequencer mode, the block producer is active. It accepts transactions that have passed RPC-side
validation, keeps them in the mempool, selects transactions into batches, proves those batches, assembles proposed
blocks, and coordinates validation and commitment.

The sequencer mempool is modeled as a directed acyclic graph (DAG) of in-flight state transitions. A child depends on a
parent when it consumes state produced by that parent, such as an output note or a new account state. This lets the
block producer select only transactions and batches whose ancestors are already selected, while preserving the chain
rule that later state transitions cannot be committed before the state they build on.

Internally, the mempool maintains separate DAGs for transactions awaiting batching and batches awaiting inclusion in a
block. Reverting a transaction or batch also reverts its descendants, and the DAG invariant avoids dependency cycles
that would force several interdependent items to be committed atomically in the same block.

### Full Node

When `node` runs in full-node mode, the block producer syncs blocks from an upstream RPC source, stores the resulting
state locally, and serves a local RPC API. It does not maintain a sequencing mempool or produce new blocks.

## License

This project is [MIT licensed](../../LICENSE).
