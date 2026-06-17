---
title: "Operation"
sidebar_position: 4
---

<!-- markdownlint-disable MD033 MD041 -->

import Tabs from "@theme/Tabs"; import TabItem from "@theme/TabItem";

# Operation

Start a full node with an upstream RPC source:

<Tabs groupId="full-node-runtime" defaultValue="native">
  <TabItem value="native" label="Native binary">

```bash
miden-node full \
  --data-directory full-node-data \
  --rpc.listen 127.0.0.1:57291 \
  --sync.block-source.url http://upstream-node:57291
```

Bind `--rpc.listen` to `127.0.0.1` unless the RPC endpoint is intentionally exposed through your own networking layer.

  </TabItem>
  <TabItem value="docker" label="Docker image">

```bash
docker run --rm --name miden-full-node \
  -v miden-full-node-data:/data \
  -p 127.0.0.1:57291:57291 \
  ghcr.io/0xmiden/miden-node:<release-tag> \
  miden-node full \
  --data-directory /data \
  --rpc.listen 0.0.0.0:57291 \
  --sync.block-source.url http://upstream-node:57291
```

The Docker port publish binds the RPC endpoint to `127.0.0.1` on the host. The node listens on `0.0.0.0` inside the
container so Docker can route the mapped port.

  </TabItem>
</Tabs>

<!-- markdownlint-enable MD033 MD041 -->

The full node syncs blocks and proofs from the upstream RPC, stores local state, and serves its own RPC API. It does not
produce blocks.
