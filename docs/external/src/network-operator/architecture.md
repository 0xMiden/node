---
title: "Architecture"
sidebar_position: 1
---

# Network Architecture

A Miden network is operated around one sequencer. The sequencer owns network progression, produces
blocks, serves public RPC, and coordinates with trusted internal services.

## Example Architecture

```text
Clients, wallets, applications
              |
        Load balancer
              |
      Public RPC full nodes
              |
   Block/proof subscriptions
              |
          Sequencer
       /      |      \
      /       |       \
Validator  NTX builder  Remote batch/block provers
              |
       Remote tx prover

Network monitor observes RPC, validator, provers, explorer, faucet, and note transport.
```

## Components and Roles

| Component | Binary | Role | Public exposure |
|---|---|---|---|
| Sequencer | `miden-node sequencer` | Produces blocks, owns canonical network progression, and serves RPC | Public RPC only |
| Full node | `miden-node full` | Replicates blocks and proofs and serves local or scaled RPC | Optional public RPC |
| Validator | `miden-validator` | Validates transactions and blocks, then signs blocks | Internal only |
| NTX builder | `miden-ntx-builder` | Builds network transactions from network notes | Internal only |
| Remote prover | `miden-remote-prover` | Offloads transaction, batch, or block proof generation | Internal only |
| Network monitor | `miden-network-monitor` | Provides health checks and an operator dashboard | Operator-facing |

The repository's Docker Compose setup is useful as a local connectivity reference for these
services. Operators should not treat it as a production deployment model.
