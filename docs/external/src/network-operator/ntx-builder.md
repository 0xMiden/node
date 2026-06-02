---
title: "NTX Builder"
sidebar_position: 5
---

# NTX Builder

The network transaction builder follows committed blocks, tracks network notes, constructs network
transactions, proves them locally or through a remote transaction prover, and submits them through
the sequencer RPC.

## Start

```sh
miden-ntx-builder start \
  --listen 0.0.0.0:50301 \
  --rpc.url http://sequencer:57291 \
  --data-directory ntx-builder-data
```

If a remote transaction prover is available, configure it with:

```sh
miden-ntx-builder start \
  --listen 0.0.0.0:50301 \
  --rpc.url http://sequencer:57291 \
  --tx-prover.url http://tx-prover:50051 \
  --data-directory ntx-builder-data
```

The NTX builder's gRPC API is internal. The sequencer RPC uses it for network-note status queries.

Use `miden-ntx-builder start --help` for the complete current option list.
