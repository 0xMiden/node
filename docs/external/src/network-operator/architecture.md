---
title: "Architecture"
sidebar_position: 1
---

# Network Architecture

A Miden network is operated around one sequencer node. The sequencer owns network progression, produces blocks, serves
RPC, and coordinates with trusted internal services.

## Example Architecture

![Miden network operator architecture](../img/operator_architecture.svg)

The public entry points are the gRPC RPC API and the gRPC prover API. Each entry point has its own load balancer: RPC
requests fan out to full nodes, while prover requests fan out to prover workers.

The diagram shows the service topology. The main data flows are:

| Flow                                | Carries                         |
| ----------------------------------- | ------------------------------- |
| Sequencer to full nodes             | Block stream                    |
| Full nodes to sequencer             | Transaction submissions         |
| Sequencer to validator              | Transactions and proposed block |
| Validator to sequencer              | Signed block                    |
| Sequencer to NTX builder            | Block stream                    |
| NTX builder to sequencer            | Network transactions            |
| NTX builder to prover load balancer | Transaction proof jobs          |

Network monitor observes RPC, validator, provers, explorer, faucet, and note transport (an independent service).

## Components and Roles

| Component       | Binary                  | Role                                                                | Public exposure     |
| --------------- | ----------------------- | ------------------------------------------------------------------- | ------------------- |
| Sequencer       | `miden-node sequencer`  | Produces blocks, owns canonical network progression, and serves RPC | Public RPC only     |
| Full node       | `miden-node full`       | Replicates blocks and proofs and serves local or scaled RPC         | Optional public RPC |
| Validator       | `miden-validator`       | Validates transactions and blocks, then signs blocks                | Internal only       |
| NTX builder     | `miden-ntx-builder`     | Builds network transactions from network notes                      | Internal only       |
| Remote prover   | `miden-remote-prover`   | Offloads transaction, batch, or block proof generation              | Internal only       |
| Network monitor | `miden-network-monitor` | Provides health checks and an operator dashboard                    | Operator-facing     |

The repository's Docker Compose setup is useful as a local connectivity reference for these services. Operators should
not treat it as a production deployment model.
