---
title: "Bootstrap and Genesis"
sidebar_position: 2
---

# Bootstrap and Genesis

The validator creates and signs the genesis block. The sequencer node and services that need trusted genesis state are
then initialized from that signed genesis block.

## Basic Sequence

Create and sign the genesis block:

```sh
miden-validator bootstrap \
  --data-directory validator-data \
  --genesis-block-directory genesis-data \
  --accounts-directory accounts
```

Initialize the sequencer's node storage from the signed genesis block:

```sh
miden-node bootstrap \
  --data-directory node-data \
  --file genesis-data/genesis.dat
```

Initialize the network transaction builder from the same signed genesis block:

```sh
miden-ntx-builder bootstrap \
  --data-directory ntx-builder-data \
  --file genesis-data/genesis.dat
```

For deployments with external key management, configure the validator key during bootstrap and startup with the
validator's KMS options. The signed genesis block is the trust anchor for every service that joins the network.
