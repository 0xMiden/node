---
title: "Full Node Runner Guide"
sidebar_position: 0
---

# Full Node Runner Guide

Full node runners follow an existing Miden network. They run `miden-node full`, sync committed blocks and block proofs
from an upstream RPC source, keep local node state, and serve a local RPC endpoint for applications, indexers,
explorers, or infrastructure.

Full node runners do not operate the sequencer, validator, or network transaction builder for a public network. Those
services belong to the network operator.

Use this guide when you want your own RPC endpoint or local replicated state for an existing network.
