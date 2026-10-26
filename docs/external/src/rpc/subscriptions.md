---
title: "Subscriptions"
sidebar_position: 2
---

# Subscriptions

The RPC API exposes two server-streaming methods for consumers that need to follow network progress.

## BlockSubscription

`BlockSubscription` streams committed blocks starting from `block_from`, inclusive. The server first replays historical
blocks, then continues streaming live blocks as they are committed.

Each response includes:

- `block`: the serialized block.
- `committed_chain_tip`: the current committed chain tip observed when the item was emitted.
- `protocol_config`: the active configuration, included with the first response and when its commitment changes.

Verify each configuration against the accompanying block header. Retain the configuration for subsequent responses that
omit it. A new subscription includes the first block's configuration, even when `block_from` is not genesis.

## ProofSubscription

`ProofSubscription` streams block proofs starting from `block_from`, inclusive. The server first replays existing
proofs, then continues streaming live proofs as they are generated.

Each response includes:

- `block_num`: the block number the proof corresponds to.
- `proof`: the serialized block proof.
- `proven_chain_tip`: the proven chain tip observed when the item was emitted.

## Consumers

Full nodes use both streams to replicate state from an upstream source. Indexers, explorers, and monitoring services can
also use the streams to ingest block data without repeatedly polling by block number.

Consumers should persist their local tip before acknowledging work internally. If a stream closes, reconnect from the
last persisted local tip. The node does not cap the number of concurrent block or proof subscriptions. Slow consumers
are disconnected with `RESOURCE_EXHAUSTED` and can reconnect immediately. Resume from local state because buffered items
may not have been delivered before disconnection.
