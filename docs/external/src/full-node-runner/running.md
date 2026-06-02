---
title: "Running"
sidebar_position: 2
---

# Running

Start a full node with an upstream RPC source:

```sh
miden-node full \
  --rpc.listen 0.0.0.0:57291 \
  --sync.block-source.url http://upstream-node:57291 \
  --data-directory full-node-data
```

The full node syncs blocks and proofs from the upstream RPC, stores local state, and serves its own
RPC API. It does not produce blocks.
