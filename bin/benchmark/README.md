# Miden benchmark

A binary for measuring transaction throughput on a Miden node by submitting locally-generated proven transactions over
RPC and reporting submission ack rate, block inclusion rate, and end-to-end latency.

## Overview

End-to-end benchmarking is split into two phases because of proof generation is expensive and shouldn't be on the
critical path of the throughput measurement:

1. **`create-proofs`**: Generates a faucet, N wallets, and `2 * N` proven transactions (one mint and one consume per
   wallet). By default each proof is produced locally with `LocalTransactionProver`; pass `--remote-prover-url` to
   offload proving to a remote prover (see [Using a remote prover](#using-a-remote-prover)). Each proof is bound to the
   chain state of the target node at the moment of generation (genesis commitment, reference block, initial account
   commitments, input note nullifiers). The bundle is written to `./benchmark-proofs/` as serialized blobs.
2. **`run-benchmark`**: Loads the bundle from disk and submits it to the node's RPC. Mints are submitted sequentially
   (each mutates the shared faucet, so order matters) and consumes are submitted with bounded concurrency. After
   submission, the run waits a few blocks and scans them to compute inclusion rate, inclusion TPS, and submit/inclusion
   latency percentiles.

Each proof takes seconds of real proving, so generating a bundle once and re-running submissions against it is the right
way to iterate on the node's mempool / block-producer / store throughput. See
[Re-using proofs](#re-using-proofs-across-runs) below.

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

Mints go in sequentially, then consumes with the requested concurrency, then the run waits `--wait-blocks` blocks before
scanning for inclusion. Per-phase ack rate, RPC latency percentiles, inclusion rate, and inclusion TPS are printed at
the end.

### Using a remote prover

Pass `--remote-prover-url` to `create-proofs` to offload STARK proving to a remote prover instead of producing proofs
locally:

```sh
miden-benchmark create-proofs \
  --rpc-url           http://127.0.0.1:57291 \
  --num-transactions  100 \
  --remote-prover-url http://prover.example.com:50051
```

The benchmark paces proving requests so that an autoscaling prover fleet has time to spin up additional workers before
being saturated:

- Dispatch starts at **1 req/s** and bumps by 1 req/s every **3 minutes**, up to **10 req/s**, and then holds at 10
  req/s for the rest of the run.
- Up to **64** proving requests may be in flight at once (independent of the rate cap).
- A retryable gRPC error from the prover (`ResourceExhausted`, `Unavailable`, `DeadlineExceeded`, or any transport-level
  failure) **freezes the ramp** at the current step for the rest of the run, and the failing request is retried with
  exponential backoff (500ms x 2\*\*n, capped at 30s, up to 10 attempts).
- If the prover URL is unreachable or a non-retryable error is returned, `create-proofs` exits with a non-zero status
  after the retry budget is exhausted.

Mint executions remain sequential (each mint mutates the shared faucet, so ordering matters), but proving runs
concurrently under the rate limiter. Consume executions are also serial today, with concurrent proving.

## Re-using proofs across runs

A `ProvenTransaction` is pinned to the chain state it was generated against:

- the node's genesis commitment,
- the reference block header,
- the initial account commitment of the account being modified,
- the input note nullifiers.

Once a tx is included in a block, the node's state advances nullifiers are recorded and account commitments change.
Re-submitting the same proven tx is rejected because the chain has moved past the state the proof was built against.

**Useful tip: clone the node's data directory before each benchmark run.** If you snapshot the data directory while the
node is stopped, then _clone_ the snapshot every time before bringing the node back up, the proofs in
`./benchmark-proofs/` stay valid indefinitely. Each run is:

1. Stop the node.
2. Replace the node's working data directory with a fresh copy of the snapshot.
3. Start the node.
4. `miden-benchmark run-benchmark`.

## Starting the node

The benchmark needs a running Miden node with a reachable RPC endpoint. The node runs as a single `miden-node sequencer`
process (store + block-producer + public RPC combined); the validator and ntx-builder are separate processes, and the
ntx-builder requires a transaction prover.

### Option A: one-shot script (easiest)

`scripts/bench-local.sh` bootstraps a fresh validator + node + ntx-builder, starts the stack plus a local transaction
prover, runs `create-proofs` then `run-benchmark`, and tears everything down on exit. It expects the binaries on
`$PATH`:

```sh
make install-node install-validator install-ntx-builder install-remote-prover install-benchmark

scripts/bench-local.sh                       # 5 tx pairs, local prover
N_TXS=20 scripts/bench-local.sh              # 20 tx pairs
USE_REMOTE_PROVER=1 scripts/bench-local.sh   # offload create-proofs to the remote prover
```

Logs and data land under `./bench-local-run/`.

### Option B: docker-compose

The repo's `docker-compose.yml` wires up all node components plus telemetry, and bootstraps genesis automatically the
first time it comes up. From the repo root:

```sh
make local-network-build   # build the node/validator/ntx-builder/prover images
make local-network-up      # bootstrap (first run) and start the stack; RPC at http://127.0.0.1:57291
```

- Follow logs with `make local-network-logs`.
- Stop the stack (preserving volumes) with `make local-network-down`.
- Stop and wipe volumes (forces a fresh genesis next time) with `make local-network-delete`.

### Option C: running the binaries directly

Install the binaries:

```sh
make install-node install-validator install-ntx-builder install-remote-prover
```

Bootstrap a fresh data directory (one-time). The validator creates the genesis block, then the node and ntx-builder
bootstrap their storage from it:

```sh
DATA=./node-data

miden-validator bootstrap \
  --data-directory          "$DATA/validator" \
  --genesis-block-directory "$DATA/genesis" \
  --accounts-directory      "$DATA/accounts"

miden-node bootstrap \
  --data-directory "$DATA/node" \
  --file           "$DATA/genesis/genesis.dat"

miden-ntx-builder bootstrap \
  --data-directory "$DATA/ntx-builder" \
  --file           "$DATA/genesis/genesis.dat"
```

Start each component. The example runs them in the background and captures logs under `./logs/`. For an interactive run,
drop the trailing `&` and put each command in its own terminal.

```sh
mkdir -p logs
DATA=./node-data

nohup miden-validator start \
  --listen         127.0.0.1:50101 \
  --data-directory "$DATA/validator" \
  > logs/validator.log 2>&1 &

# The ntx-builder needs a transaction prover, so start one regardless.
nohup miden-remote-prover \
  --port     50051 \
  --kind     transaction \
  --capacity 32 \
  --timeout  300s \
  > logs/remote-prover.log 2>&1 &

# The node runs store + block-producer + RPC in a single sequencer process.
nohup miden-node sequencer \
  --data-directory                            "$DATA/node" \
  --rpc.listen                                127.0.0.1:57291 \
  --validator.url                             http://127.0.0.1:50101 \
  --ntx-builder.url                           http://127.0.0.1:50301 \
  --batch.max-txs                             1024 \
  --block.max-batches                         64 \
  --block.interval                            2s \
  --batch.interval                            100ms \
  --batch.workers                             16 \
  --mempool.tx-capacity                       1000000 \
  --rpc.grpc.timeout                          24h \
  --rpc.grpc.max-connection-age               24h \
  --rpc.rate-limit.burst-size                 100000 \
  --rpc.rate-limit.replenish-per-second       100000 \
  --rpc.rate-limit.max-concurrent-connections 1000000 \
  > logs/node.log 2>&1 &

nohup miden-ntx-builder start \
  --listen         127.0.0.1:50301 \
  --rpc.url        http://127.0.0.1:57291 \
  --tx-prover.url  http://127.0.0.1:50051 \
  --data-directory "$DATA/ntx-builder" \
  > logs/ntx-builder.log 2>&1 &
```

#### Stopping the node

```sh
pkill -f miden-ntx-builder
pkill -f 'miden-node sequencer'
pkill -f miden-remote-prover
pkill -f miden-validator
```

## Lifting the TPS ceiling

At default settings the block-producer caps end-to-end inclusion at **~21 tx/s**, well below the protocol's hard limit.

### The layered ceiling

| Cap                              | Default | Protocol max | Knob                    |
| -------------------------------- | ------- | ------------ | ----------------------- |
| Transactions per batch           | 8       | 1024         | `--batch.max-txs`       |
| Batches per block                | 8       | 64           | `--block.max-batches`   |
| Block interval                   | 3 s     | n/a          | `--block.interval`      |
| Batch interval                   | 1 s     | n/a          | `--batch.interval`      |
| Concurrent batch-builder workers | 2       | n/a          | `--batch.workers`       |
| Inflight mempool transactions    | ~1280   | n/a          | `--mempool.tx-capacity` |

Block throughput ceiling = `max_batches_per_block x max_txs_per_batch / block.interval`.

- Defaults: `8 x 8 / 3 s ~= 21 tx/s`.
- Protocol max with a 1 s block: `64 x 1024 / 1 s = 65 536 tx/s`.

Protocol caps are enforced at startup (in `bin/node/src/commands/block_producer.rs`) and require a protocol-level change
to lift. Everything else is operator configuration.

### The batch-builder worker pool (`--batch.workers`)

`--batch.workers` (env `MIDEN_NODE_BATCH_WORKERS`) sets how many batches the block-producer keeps proving in parallel.
Each worker is responsible for one in-flight batch proof — locally with the built-in prover, or remotely if
`--batch-prover.url` is set. The default is **2**. Once `--batch.max-txs` and `--block.max-batches` are pushed up, this
worker count is the single setting that determines how fast the block-producer can refill the mempool's batch slots;
leaving it at 2 caps effective throughput well before the new block capacity becomes reachable.

Rough sizing:

- **With local batch proving** (no `--batch-prover.url`): raise to roughly the number of physical CPU cores on the
  block-producer host. More than that just over-subscribes the cores running the prover.
- **With a remote batch prover**: raise to whatever the remote service can service in parallel (i.e. its own worker
  count). The block-producer workers are now mostly waiting on I/O, so the bound is the remote prover's capacity, not
  local CPU.

## License

This project is [MIT licensed](../../LICENSE).
