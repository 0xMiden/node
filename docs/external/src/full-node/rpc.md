---
title: "RPC"
sidebar_position: 6
---

# RPC

A full node serves the public `rpc.Api` service from its local replicated state. Use it as a private or dedicated RPC
endpoint for applications, indexers, explorers, and other infrastructure that should not depend directly on official
public RPC capacity.

## Local Queries

Read queries are served from the full node's local state. This includes account, block, note, and sync methods.

The network-note debugging endpoint, `GetNetworkNoteStatus`, is the exception: it depends on NTX builder state rather
than replicated chain state, so full nodes forward it to the configured upstream RPC source.

## Transaction Submission

Full nodes do not sequence transactions. `SubmitProvenTx` and `SubmitProvenTxBatch` are forwarded to the configured
upstream RPC source. If the upstream source is another full node, the request is forwarded again until it reaches the
sequencer.

This lets clients submit through a nearby full node while preserving the sequencer as the only block-producing node.

## Health Check

The full node exposes the standard gRPC health protocol at `grpc.health.v1.Health/Check`. Use this endpoint to probe
readiness from load balancers, orchestrators, or monitoring infrastructure.

The endpoint reports `NOT_SERVING` while the node is syncing and its local state is too far behind the chain tip. It
transitions to `SERVING` once it has caught up sufficiently to serve accurate read queries.

## Scaling Throughput

Full nodes sync from their upstream source using:

- `BlockSubscription` for committed signed blocks.
- `ProofSubscription` for block proofs.

You can daisy-chain full nodes and fan out downstream nodes to scale read throughput.

```text
                             ┌── Full node
Official RPC ── Full node ───┼── Full node
                             └── Full node
```

Each downstream full node subscribes to blocks and proofs from its upstream source, stores local state, and serves its
own read RPC traffic. This can reduce load on the sequencer or official public RPC endpoint.

See the [RPC subscriptions guide](../rpc/subscriptions) for stream semantics and reconnect behavior.
