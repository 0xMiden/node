---
title: "Configuration"
sidebar_position: 5
---

# Configuration

Common full node options include:

| Option | Purpose |
|---|---|
| `--data-directory` | Directory containing local node state. |
| `--rpc.listen` | Socket address for the local public RPC API. |
| `--sync.block-source.url` | Upstream RPC URL used for block and proof subscriptions. |
| `--rpc.grpc.timeout` | Maximum request duration for the local RPC server. |
| `--rpc.rate-limit.*` | Per-IP and global RPC rate limiting options. |
| `--store.sqlite.connection-pool-size` | SQLite connection pool size for node storage. |

Use `miden-node full --help` for the complete current configuration surface.
