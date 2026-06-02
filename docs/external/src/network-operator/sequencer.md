---
title: "Sequencer"
sidebar_position: 3
---

# Sequencer

The sequencer is centralized network infrastructure operated by the network operator. It runs
`miden-node sequencer`, produces blocks, serves public RPC, and connects to the validator and network
transaction builder.

## Start

```sh
miden-node sequencer \
  --rpc.listen 0.0.0.0:57291 \
  --data-directory node-data \
  --validator.url http://validator:50101 \
  --ntx-builder.url http://ntx-builder:50301
```

Only the public RPC listener should be externally reachable. The validator, NTX builder, and prover
URLs are trusted internal services.

## Common Configuration

| Option | Purpose |
|---|---|
| `--rpc.listen` | Public RPC socket exposed by the sequencer. |
| `--validator.url` | Internal validator service URL. |
| `--ntx-builder.url` | Internal network transaction builder service URL. |
| `--batch.interval` | Batch production interval. |
| `--block.interval` | Block production interval. |
| `--batch-prover.url` | Optional remote batch prover URL. |
| `--block-prover.url` | Optional remote block prover URL. |

Use `miden-node sequencer --help` for the complete current option list.
