---
title: "Remote Provers"
sidebar_position: 7
---

# Remote Provers

Remote provers offload expensive transaction, batch, or block proof generation to dedicated machines. Each
`miden-remote-prover` instance is configured for one proof type.

## Start

Run one prover instance per proof kind:

```bash
miden-remote-prover --kind transaction --port 50051
miden-remote-prover --kind batch --port 50052
miden-remote-prover --kind block --port 50053
```

Connect services to the relevant prover URLs:

| Consumer                        | Option               |
| ------------------------------- | -------------------- |
| Sequencer batch proving         | `--batch-prover.url` |
| Sequencer block proving         | `--block-prover.url` |
| NTX builder transaction proving | `--tx-prover.url`    |

Remote provers are internal services. Put load balancing, service discovery, and admission control outside the prover
binary when a deployment needs them.
