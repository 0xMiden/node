---
title: "Full Node Guide"
sidebar_position: 0
---

# Full Node Guide

Run a full node to synchronize to an existing Miden network. The full node provides the complete gRPC API and can be
used to avoid rate-limiting on official RPC endpoints. This is particularly useful for heavy RPC users and provides a
more robust implementation for explorers and indexers to maintain sync with the network, at the cost of storing the
network data.

Full nodes can also be daisy-chained to provide horizontal RPC scaling and throughput.

Use this guide when you want your own RPC endpoint or local replicated state for an existing network.

The lifecycle pages use the `miden-node` command directly. Choose an installation method first, then follow the quick
start.

Start with [Installation](/full-node/installation) and [Quick Start](/full-node/quick-start), then use the remaining
pages for detailed bootstrap, operation, RPC, migration, and configuration guidance.
