---
title: "Troubleshooting"
sidebar_position: 8
---

# Troubleshooting

## Data Directory Is Empty

Run `miden-node bootstrap` before starting `miden-node full`.

## Wrong Genesis

If the full node was bootstrapped from a different genesis block than its upstream source, recreate the data directory
from the correct trusted genesis source.

## Subscription Lag

If the upstream closes a subscription with `DATA_LOSS`, restart sync from the full node's last local tip. Persistent
repeated lag usually means the node or upstream needs more capacity.

## Port Already In Use

Change `--rpc.listen` or stop the process already bound to the port.
