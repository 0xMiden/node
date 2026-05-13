# Miden benchmark

A binary for measuring transaction throughput on a Miden node by submitting locally-generated proven transactions over RPC and reporting submission ack rate, block inclusion rate, and end-to-end latency.

## Overview

End-to-end benchmarking is split into two phases because of proof generation is expensive and shouldn't be on the critical path of the throughput measurement:

1. **`create-proofs`**: Generates a faucet, N wallets, and `2 * N` proven
   transactions (one mint and one consume per wallet). Each proof is produced
   locally with `LocalTransactionProver` and is bound to the chain state of
   the target node at the moment of generation (genesis commitment, reference
   block, initial account commitments, input note nullifiers). The bundle is
   written to `./benchmark-proofs/` as serialized blobs.
2. **`run-benchmark`**: Loads the bundle from disk and submits it to the
   node's RPC. Mints are submitted sequentially (each mutates the shared
   faucet, so order matters) and consumes are submitted with bounded
   concurrency. After submission, the run waits a few blocks and scans them
   to compute inclusion rate, inclusion TPS, and submit/inclusion latency
   percentiles.

Each proof takes seconds of real proving, so generating a bundle once and re-running submissions against it is the right way to iterate on the node's mempool / block-producer / store throughput. See [Re-usingproofs](#re-using-proofs-across-runs) below.

## Building

```sh
make install-benchmark
```

## Usage

### Generate proven transactions

```sh
miden-benchmark create-proofs \
  --rpc-url http://127.0.0.1:57291 \
  --num-transactions 100
```

Writes the bundle to `./benchmark-proofs/`:

- `mint_txs.bin`, `mint_tx_inputs.bin`
- `consume_txs.bin`, `consume_tx_inputs.bin`

### Submit them

```sh
miden-benchmark run-benchmark \
  --rpc-url http://127.0.0.1:57291 \
  --concurrency 32 \
  --wait-blocks 3
```

Mints go in sequentially, then consumes with the requested concurrency, then the run waits `--wait-blocks` blocks before scanning for inclusion. Per-phase ack rate, RPC latency percentiles, inclusion rate, and inclusion TPS are printed at the end.

## Re-using proofs across runs

A `ProvenTransaction` is pinned to the chain state it was generated against:

- the node's genesis commitment,
- the reference block header,
- the initial account commitment of the account being modified,
- the input note nullifiers.

Once a tx is included in a block, the node's state advances nullifiers are recorded and account commitments change. Re-submitting the same proven tx is rejected because the chain has moved past the state the proof was built against.

**Useful tip: clone the node's data directory before each benchmark run.** If you snapshot the data directory while the node is stopped, then *clone* the snapshot every time before bringing the node back up, the proofs in `./benchmark-proofs/` stay valid indefinitely. Each run is:

1. Stop the node.
2. Replace the node's working data directory with a fresh copy of the
   snapshot.
3. Start the node.
4. `miden-benchmark run-benchmark`.

## Starting the node

The benchmark needs a running Miden node with a reachable RPC endpoint.

### Option A: docker-compose (recommended for benchmarking)

The repo's `docker-compose.yml` wires up all node components (`store`,
`validator`, `block-producer`, `rpc`, `ntx-builder`) plus telemetry. From the
repo root:

```sh
make docker-build      # build miden-node and miden-validator images
make compose-genesis   # wipe the volume, bootstrap a fresh genesis
make compose-up        # start the stack (RPC at http://127.0.0.1:57291)
```

Stop with `make compose-down`.

### Option B: running `miden-node` and `miden-validator` directly

Install both binaries:

```sh
make install-node
make install-validator
```

Bootstrap a fresh data directory (one-time):

```sh
DATA=./node-data

miden-validator bootstrap \
  --data-directory          $DATA/validator \
  --genesis-block-directory $DATA/genesis \
  --accounts-directory      $DATA/accounts

miden-node store bootstrap \
  --data-directory $DATA/store \
  --genesis-block  $DATA/genesis/genesis.dat
```

Start each component. The example below backgrounds them with `nohup` and captures logs under `./logs/`. For an interactive run, drop the `nohup` / `&` and put each command in its own terminal.

```sh
mkdir -p logs

nohup miden-validator start \
  --listen 127.0.0.1:50101 \
  --data-directory "$DATA/validator" \
  > logs/validator.log 2>&1 &

nohup miden-node store start \
  --rpc.listen            127.0.0.1:50001 \
  --ntx-builder.listen    127.0.0.1:50002 \
  --block-producer.listen 127.0.0.1:50003 \
  --data-directory        "$DATA/store" \
  > logs/store.log 2>&1 &

nohup miden-node block-producer start \
  --listen 127.0.0.1:50201 \
  --store.url     http://127.0.0.1:50003 \
  --validator.url http://127.0.0.1:50101 \
  > logs/block-producer.log 2>&1 &

nohup miden-node rpc start \
  --listen 127.0.0.1:57291 \
  --store.url          http://127.0.0.1:50001 \
  --block-producer.url http://127.0.0.1:50201 \
  --validator.url      http://127.0.0.1:50101 \
  > logs/rpc.log 2>&1 &

nohup miden-node ntx-builder start \
  --listen 127.0.0.1:50301 \
  --store.url          http://127.0.0.1:50002 \
  --block-producer.url http://127.0.0.1:50201 \
  --validator.url      http://127.0.0.1:50101 \
  --data-directory     "$DATA/ntx-builder" \
  > logs/ntx-builder.log 2>&1 &
```

#### Stopping the node

```sh
pkill -f miden-validator
pkill -f 'miden-node store'
pkill -f 'miden-node block-producer'
pkill -f 'miden-node rpc'
pkill -f 'miden-node ntx-builder'
# Or, if no other miden binaries are running:
pkill -f 'miden-(node|validator)'
```
## Lifting the TPS ceiling

At default settings the block-producer caps end-to-end inclusion at **~21 tx/s**, well below the protocol's hard limit.

### The layered ceiling

| Cap                                          | Default | Protocol max | Knob                           |
| -------------------------------------------- | ------- | ------------ | ------------------------------ |
| Transactions per batch                       | 8       | 1024         | `--max-txs-per-batch`          |
| Batches per block                            | 8       | 64           | `--max-batches-per-block`      |
| Block interval                               | 3 s     | n/a          | `--block.interval`             |
| Batch interval                               | 1 s     | n/a          | `--batch.interval`             |
| Concurrent batch-builder workers             | 2       | n/a          | `--batch.workers`              |
| Inflight mempool transactions                | ~1280   | n/a          | `--mempool.tx-capacity`        |

Block throughput ceiling = `max_batches_per_block x max_txs_per_batch / block.interval`.

- Defaults: `8 x 8 / 3 s ~= 21 tx/s`.
- Protocol max with a 1 s block: `64 x 1024 / 1 s = 65 536 tx/s`.

Protocol caps are enforced at startup (in `bin/node/src/commands/block_producer.rs`) and require a protocol-level change to lift. Everything else is operator configuration.

### The batch-builder worker pool (`--batch.workers`)

`--batch.workers` (env `MIDEN_NODE_BLOCK_PRODUCER_BATCH_WORKERS`) sets how many batches the block-producer keeps proving in parallel. Each worker is responsible for one in-flight batch proof — locally with the built-in prover, or remotely if `--batch-prover.url` is set. The default is **2**. Once `--max-txs-per-batch` and `--max-batches-per-block` are pushed up, this worker count is the single setting that determines how fast the block-producer can refill the mempool's batch slots; leaving it at 2 caps effective throughput well before the new block capacity becomes reachable.

Rough sizing:

- **With local batch proving** (no `--batch-prover.url`): raise to roughly
  the number of physical CPU cores on the block-producer host. More than
  that just over-subscribes the cores running the prover.
- **With a remote batch prover**: raise to whatever the remote service can
  service in parallel (i.e. its own worker count). The block-producer
  workers are now mostly waiting on I/O, so the bound is the remote
  prover's capacity, not local CPU.

### Bench-tuned recipe

Replace the `block-producer` invocation in the [Option B](#option-b--running-miden-node-and-miden-validator-directly)
startup block with:

```sh
nohup miden-node block-producer start \
  --listen 127.0.0.1:50201 \
  --store.url            http://127.0.0.1:50003 \
  --validator.url        http://127.0.0.1:50101 \
  --max-txs-per-batch     1024     `# protocol max`        \
  --max-batches-per-block 64       `# protocol max`        \
  --block.interval        2s       `# default 3s`          \
  --batch.interval        100ms    `# default 1s`          \
  --batch.workers         16       `# default 2`           \
  --mempool.tx-capacity   1000000  `# default ~1280`       \
  > logs/block-producer.log 2>&1 &
```

## License

This project is [MIT licensed](../../LICENSE).
