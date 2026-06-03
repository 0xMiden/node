---
title: "Architecture"
sidebar_position: 1
---

# Network Architecture

A Miden network is organized around a single sequencer node. The sequencer owns network progression, produces blocks,
serves RPC, and coordinates with trusted internal services.

## Example Architecture

![Miden network operator architecture](../img/operator_architecture.svg)

The public entry points are the gRPC RPC API and the gRPC prover API. Each entry point has its own load balancer: RPC
requests fan out to full nodes, while prover requests fan out to prover workers.

The diagram shows the service topology. The main data flows are:

Network monitor observes RPC, validator, provers, explorer, faucet, and note transport (an independent service).

## Components and Roles

| Component       | Binary                  | Role                                                                |
| --------------- | ----------------------- | ------------------------------------------------------------------- |
| Sequencer       | `miden-node sequencer`  | Produces blocks, owns canonical network progression, and serves RPC |
| Full node       | `miden-node full`       | Replicates blocks and proofs and serves local or scaled RPC         |
| Validator       | `miden-validator`       | Validates transactions and blocks, then signs blocks                |
| NTX builder     | `miden-ntx-builder`     | Builds network transactions from network notes                      |
| Prover          | `miden-remote-prover`   | Offloads transaction, batch, or block proof generation              |
| Network monitor | `miden-network-monitor` | Provides health checks and an operator dashboard                    |
