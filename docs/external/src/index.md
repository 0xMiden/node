---
sidebar_position: 0
title: "Miden Node"
---

# Miden Node

The Miden node repository contains the infrastructure needed to run and follow a Miden network. The
public documentation is organized by audience:

- Use [Local Node Development](./local-node-development) to run a disposable local network from a repository checkout.
- Use the [Full Node Runner Guide](./full-node-runner/) to follow an existing network with `miden-node full`.
- Use the [gRPC API](./rpc/) section when integrating wallets, clients, indexers, explorers, or other services.
- Use the [Network Operator Guide](./network-operator/) when operating a Miden network's centralized sequencing
  infrastructure.

## Roles

A Miden network has one sequencer. The sequencer is centralized network infrastructure operated by
the network operator. It produces blocks, coordinates with internal services, and exposes the public
RPC API for the network.

Full node runners do not run a sequencer for an existing network. They run `miden-node full`, sync
committed blocks and block proofs from an upstream RPC source, keep local state, and serve a local
RPC endpoint for applications, indexers, explorers, or higher-volume infrastructure.

Network operators also run supporting internal services such as the validator, network transaction
builder, remote provers, and network monitor.

## Versioned Commands

The node binaries and protobuf schema are still under active development. When using examples from
these docs, check out the repository tag or branch that matches the binaries or Docker images you
intend to run. For exhaustive command-line options, use each binary's help output:

```sh
miden-node --help
miden-validator --help
miden-ntx-builder --help
miden-remote-prover --help
miden-network-monitor --help
```

## Feedback

Please report any issues, ask questions or leave feedback in the node repository
[here](https://github.com/0xMiden/node/issues/new/choose).

This includes outdated, misleading, incorrect or just plain confusing information :)
