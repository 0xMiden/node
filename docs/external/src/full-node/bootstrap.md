---
title: "Bootstrap"
sidebar_position: 3
---

<!-- markdownlint-disable MD033 MD041 -->

import Tabs from "@theme/Tabs"; import TabItem from "@theme/TabItem";

# Bootstrap

A full node must perform one-time initialization by bootstrapping its local chain state to the target network's genesis
block.

<Tabs groupId="full-node-runtime" defaultValue="native">
  <TabItem value="native" label="Native binary">

For an official network:

```bash
miden-node bootstrap \
  --data-directory full-node-data \
  --network <network>
```

For a local or custom network:

```bash
miden-node bootstrap \
  --data-directory full-node-data \
  --file genesis.dat
```

The data directory must be empty when bootstrapping.

  </TabItem>
  <TabItem value="docker" label="Docker image">

For an official network:

```bash
docker run --rm \
  -v miden-full-node-data:/data \
  ghcr.io/0xmiden/miden-node:<release-tag> \
  miden-node bootstrap \
  --data-directory /data \
  --network <network>
```

For a local or custom network:

```bash
docker run --rm \
  -v miden-full-node-data:/data \
  -v "$PWD/genesis.dat:/genesis.dat:ro" \
  ghcr.io/0xmiden/miden-node:<release-tag> \
  miden-node bootstrap \
  --data-directory /data \
  --file /genesis.dat
```

The data volume must be empty when bootstrapping.

  </TabItem>
</Tabs>

<!-- markdownlint-enable MD033 MD041 -->

Use the same node version and genesis source as the upstream network you intend to follow.
