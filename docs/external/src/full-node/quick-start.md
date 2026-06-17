---
title: "Quick Start"
sidebar_position: 2
---

<!-- markdownlint-disable MD033 MD041 -->

import Tabs from "@theme/Tabs"; import TabItem from "@theme/TabItem";

# Quick Start

Launch a testnet full node after completing [Installation](/full-node/installation).

<Tabs groupId="full-node-runtime" defaultValue="native">
  <TabItem value="native" label="Native binary">

Bootstrap an empty data directory from the official testnet genesis state:

```bash
miden-node bootstrap \
  --data-directory full-node-data \
  --network testnet
```

Start the full node and sync from the official testnet RPC endpoint:

```bash
miden-node full \
  --data-directory full-node-data \
  --rpc.listen 127.0.0.1:57291 \
  --sync.block-source.url https://rpc.testnet.miden.io
```

  </TabItem>
  <TabItem value="docker" label="Docker image">

Bootstrap an empty data volume from the official testnet genesis state:

```bash
docker run --rm \
  -v miden-full-node-data:/data \
  ghcr.io/0xmiden/miden-node:<release-tag> \
  miden-node bootstrap \
  --data-directory /data \
  --network testnet
```

Start the full node and sync from the testnet RPC endpoint:

```bash
docker run --rm --name miden-full-node \
  -v miden-full-node-data:/data \
  -p 127.0.0.1:57291:57291 \
  ghcr.io/0xmiden/miden-node:<release-tag> \
  miden-node full \
  --data-directory /data \
  --rpc.listen 0.0.0.0:57291 \
  --sync.block-source.url https://rpc.testnet.miden.io
```

The Docker port publish binds the RPC endpoint to `127.0.0.1` on the host. The node listens on `0.0.0.0` inside the
container so Docker can route the mapped port.

  </TabItem>
</Tabs>

<!-- markdownlint-enable MD033 MD041 -->

Check the local RPC endpoint from another terminal:

```bash
grpcurl -plaintext localhost:57291 rpc.Api/Status
```

The `-plaintext` flag is required for the local full node RPC listener because it does not use TLS.

Replace `testnet`, `<release-tag>`, and `https://rpc.testnet.miden.io` with the network, version, and upstream source
you intend to follow. See [Official Network URLs](/official-network-urls) for public official network endpoints.
