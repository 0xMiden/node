---
title: "Migrations"
sidebar_position: 3
---

# Migrations

When a new node binary requires storage schema changes, migrate an existing full node data directory before starting the
node:

```sh
miden-node migrate --data-directory full-node-data
```

Backwards migrations are not supported. If a data directory is older than the minimum supported schema version for a
binary, migrate forward in stages with older compatible binaries first.
