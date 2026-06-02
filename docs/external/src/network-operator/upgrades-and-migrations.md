---
title: "Upgrades and Migrations"
sidebar_position: 8
---

# Upgrades and Migrations

Network upgrades may involve binary upgrades, storage migrations, schema changes, and coordinated
service restarts.

## Node Storage Migrations

Apply pending node storage migrations before starting a newer sequencer or full-node binary:

```sh
miden-node migrate --data-directory node-data
```

Backwards migrations are not supported. If a data directory is older than the minimum supported
schema version for the target binary, migrate forward in stages with older compatible binaries
first.

## Coordination

Upgrade planning should account for RPC schema compatibility, public client expectations, validator
availability, NTX builder compatibility, prover compatibility, and monitoring coverage before the
sequencer is restarted.
