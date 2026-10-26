---
title: "Troubleshooting"
sidebar_position: 8
---

# Troubleshooting

## Increase Log Detail

Use `MIDEN_STDOUT_FILTER` to enable detailed output for the affected component. For example:

```bash
MIDEN_STDOUT_FILTER='info,user=debug,user::miden-rpc=trace' miden-node full ...
```

See [Logging](/logging) for filter precedence, all user-facing targets, container and systemd examples, and independent
OpenTelemetry filtering.

## Data Directory Is Empty

Run `miden-node bootstrap` before starting `miden-node full`.

## Wrong Genesis

If the full node was bootstrapped from a different genesis block than its upstream source, recreate the data directory
from the correct trusted genesis source.

## Subscription Lag

If the upstream closes a subscription with `RESOURCE_EXHAUSTED`, the full node fell too far behind. It reconnects from
its last local tip automatically. Persistent repeated lag usually means the node or upstream needs more capacity.

## Port Already In Use

Change `--rpc.listen` or stop the process already bound to the port.
