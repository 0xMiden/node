---
title: "Network Transaction Builder"
sidebar_position: 6
---

# Network Transaction Builder

The network transaction builder follows committed blocks, tracks network notes, constructs network transactions, proves
them with a remote transaction prover, and submits them through an RPC node. That RPC node can be the sequencer or a
full node; transaction submissions are forwarded upstream until they reach the sequencer.

## Start

```bash
miden-ntx-builder start \
  --listen 0.0.0.0:50301 \
  --rpc.url http://rpc-node:57291 \
  --rpc.auth-header-value <network-tx-auth-secret> \
  --tx-prover.url http://tx-prover:50051 \
  --data-directory ntx-builder-data
```

The configured `--rpc.url` should point at a node that can reach the sequencer, either directly or through a full-node
upstream chain.

The `--rpc.auth-header-value` value is sent as the fixed `x-miden-network-tx-auth` metadata header when the NTX builder
submits network transactions. It must match the sequencer's `--rpc.network-tx-auth-header-value`; otherwise, those
network transactions are rejected.

The network transaction builder's gRPC API is internal. External clients should request network note status through the
standard RPC API on any node. Full nodes forward these requests through their upstream RPC source until they reach a
sequencer, which resolves them by calling the network transaction builder.

Use `miden-ntx-builder start --help` for the complete current option list.
