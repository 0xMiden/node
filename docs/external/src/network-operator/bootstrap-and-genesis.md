---
title: "Bootstrap and Genesis"
sidebar_position: 3
---

<!-- markdownlint-disable MD033 MD041 -->

import Tabs from "@theme/Tabs"; import TabItem from "@theme/TabItem";

# Bootstrap and Genesis

A signed genesis block is the trust anchor for every service that joins a network. The network's validator is
responsible for creating and signing this block. On official networks, the validator is operated by a separate entity
from the network operator.

This signed block is subsequently made available for official networks at

```text
https://genesis.<network>.miden.io
```

which provides an easy method to obtain this data. This is directly supported by service bootstrap commands by passing
`--network testnet` or `--network devnet`. Bootstrap commands also support passing a file directly to cover custom
networks, or if the official URLs are not trusted.

## Bootstrap Flow

<Tabs groupId="network-operator-genesis-source" defaultValue="official">
  <TabItem value="official" label="Official network">

The official validator operator creates and signs the genesis block with the validator's KMS key:

```bash
miden-validator bootstrap \
  --data-directory validator-data \
  --genesis-block-directory genesis-data \
  --accounts-directory accounts \
  --genesis-config-file genesis.toml \
  --key.kms-id <validator-kms-key-id>
```

Upload `genesis-data/genesis.dat` so it is served at:

```text
https://genesis.<network>.miden.io
```

Initialize the sequencer's node storage from the hosted genesis block:

```bash
miden-node bootstrap \
  --data-directory node-data \
  --network testnet
```

Initialize the network transaction builder from the same hosted genesis block:

```bash
miden-ntx-builder bootstrap \
  --data-directory ntx-builder-data \
  --network testnet
```

For `devnet`, use `--network devnet` instead. The `--network` flag is shorthand for downloading the signed genesis block
from `https://genesis.<network>.miden.io`.

The same KMS key ID must be used when the official validator operator starts the validator for this network.

  </TabItem>
  <TabItem value="unofficial" label="Unofficial network">

Create and sign the genesis block with the validator's local key:

```bash
miden-validator bootstrap \
  --data-directory validator-data \
  --genesis-block-directory genesis-data \
  --accounts-directory accounts \
  --genesis-config-file genesis.toml \
  --key.hex <validator-key-hex>
```

For unofficial networks or pre-publication testing, distribute the signed genesis block file directly and initialize
services from that file:

```bash
miden-node bootstrap \
  --data-directory node-data \
  --file genesis-data/genesis.dat
```

```bash
miden-ntx-builder bootstrap \
  --data-directory ntx-builder-data \
  --file genesis-data/genesis.dat
```

  </TabItem>
</Tabs>

The validator key used during bootstrap must match the key used when starting the validator for the network.

<!-- markdownlint-enable MD033 MD041 -->
