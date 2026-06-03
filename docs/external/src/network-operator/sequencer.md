---
title: "Sequencer"
sidebar_position: 4
---

# Sequencer

The sequencer is centralized network infrastructure operated by the network operator. It runs `miden-node sequencer`,
produces blocks, serves public RPC, and connects to the validator and network transaction builder.

## Start

```bash
miden-node sequencer \
  --rpc.listen 0.0.0.0:57291 \
  --data-directory node-data \
  --validator.url http://validator:50101 \
  --ntx-builder.url http://ntx-builder:50301 \
  --rpc.network-tx-auth-header-value <network-tx-auth-secret>
```

Only the public RPC listener should be externally reachable. The validator, NTX builder, and prover URLs are trusted
internal services.

The network transaction auth value is a shared secret used to authorize network transaction submissions. It must match
the NTX builder's `--rpc.auth-header-value`; otherwise, the sequencer rejects network transactions from the builder.

## RPC Source

The sequencer implements the full RPC API and can act as an RPC source. This is useful for networks without full nodes,
for routing excess RPC load to the sequencer when it has spare capacity, or as a fallback if the available full node
capacity fails.

For larger deployments, prefer serving public RPC through full nodes so the sequencer can focus on block production.

## Failover

Full nodes replicate the committed sequencer state from their upstream block source. Because of this, a full node can be
promoted to sequencer if the active sequencer needs to be replaced.

The promotion target must be in sync with the current sequencer state. A full node that is behind the sequencer is not a
valid replacement until it has caught up to the committed chain tip.

There is always some risk of data loss during failover because full nodes follow the sequencer asynchronously. Blocks
committed by the sequencer but not yet replicated to the promoted full node may be missing from that node's local state.
The validator also retains a copy of the blocks it validated and signed, and can be used to recover missing committed
block data when this occurs.

## Common Configuration

| Option                               | Purpose                                                |
| ------------------------------------ | ------------------------------------------------------ |
| `--rpc.listen`                       | Public RPC socket exposed by the sequencer.            |
| `--rpc.network-tx-auth-header-value` | Shared secret for authorized network transaction flow. |
| `--validator.url`                    | Internal validator service URL.                        |
| `--ntx-builder.url`                  | Internal network transaction builder service URL.      |
| `--batch.interval`                   | Batch production interval.                             |
| `--block.interval`                   | Block production interval.                             |

Use `miden-node sequencer --help` for the complete current option list.
