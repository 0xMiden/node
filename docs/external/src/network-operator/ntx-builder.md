---
title: "Network Transaction Builder"
sidebar_position: 6
---

# Network Transaction Builder

The network transaction builder follows committed blocks, tracks network notes, constructs network transactions, proves
them with a remote transaction prover, and submits them through an RPC node. That RPC node can be the sequencer or a
full node; transaction submissions are forwarded upstream until they reach the sequencer.

## Start

```bash
miden-ntx-builder start \
  --listen 0.0.0.0:50301 \
  --rpc.url http://rpc-node:57291 \
  --rpc.auth-header-value <network-tx-auth-secret> \
  --tx-prover.url http://tx-prover:50051 \
  --data-directory ntx-builder-data
```

The configured `--rpc.url` should point at a node that can reach the sequencer, either directly or through a full-node
upstream chain.

The NTX builder verifies transaction encryption key attestations against the validator signing keys in its genesis data.
Existing data directories must be bootstrapped again after this storage migration so those keys are available.

The `--rpc.auth-header-value` value is sent as the fixed `x-miden-network-tx-auth` metadata header when the NTX builder
submits network transactions. It must match the sequencer's `--rpc.network-tx-auth-header-value`; otherwise, those
network transactions are rejected.

The network transaction builder's gRPC API is internal. External clients should request network note status through the
standard RPC API on any node. Full nodes forward these requests through their upstream RPC source until they reach a
sequencer, which resolves them by calling the network transaction builder.

## Note retention

The network transaction builder keeps every network note it has seen so that the note status endpoint can report it.
Notes that have been consumed are no longer needed for building transactions, so they are deleted once they are older
than the retention window. This stops consumed notes from accumulating in the database.

The window is set with `--note-retention`, in blocks, and defaults to 28800 blocks (about one day at a block interval of
three seconds). A note status request for a consumed note returns `NOT_FOUND` once the window has passed. Notes that are
still pending, and notes that were discarded after too many failed attempts, are kept regardless of their age.

Raise the value if users need to query consumed notes for longer, at the cost of a larger database.

Expired notes are deleted a few thousand at a time as blocks are applied. After an upgrade from a version that kept
consumed notes, or after lowering the value, the backlog is therefore cleared over the following blocks rather than at
once. The database file does not shrink when notes are deleted; the freed space is reused for new notes.

Deleting consumed notes relies on a database migration. When upgrading an existing data directory, apply it before
starting the service, as described in [Upgrades and Migrations](/network-operator/upgrades-and-migrations).

Use `miden-ntx-builder start --help` for the complete current option list.
