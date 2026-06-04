---
title: "Migrations"
sidebar_position: 5
---

<!-- markdownlint-disable MD033 MD041 -->

import Tabs from "@theme/Tabs"; import TabItem from "@theme/TabItem";

# Migrations

Occasionally, a new node version requires storage schema changes. These can be applied using the `migrate` command after
stopping the node.

<Tabs groupId="full-node-runtime" defaultValue="native">
  <TabItem value="native" label="Native binary">

```bash
miden-node migrate --data-directory full-node-data
```

  </TabItem>
  <TabItem value="docker" label="Docker image">

```bash
docker run --rm \
  -v miden-full-node-data:/data \
  ghcr.io/0xmiden/miden-node:<release-tag> \
  miden-node migrate --data-directory /data
```

  </TabItem>
</Tabs>

<!-- markdownlint-enable MD033 MD041 -->

Backwards migrations are not supported. If a data directory is older than the minimum supported schema version for a
release, migrate forward in stages with older compatible versions first.

The node will error on startup if any migrations have not been applied. It is safe to run the migration command if all
migrations have already been applied.
