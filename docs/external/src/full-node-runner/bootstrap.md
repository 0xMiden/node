---
title: "Bootstrap"
sidebar_position: 1
---

# Bootstrap

A full node data directory must be initialized from trusted genesis state before it can start.

For an official network:

```sh
miden-node bootstrap \
  --data-directory full-node-data \
  --network <network>
```

For a local or custom network:

```sh
miden-node bootstrap \
  --data-directory full-node-data \
  --file genesis.dat
```

Use the same genesis source as the upstream network you intend to follow.
