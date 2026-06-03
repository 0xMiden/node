---
title: "Validator"
sidebar_position: 5
---

# Validator

The validator verifies submitted transactions and proposed blocks before signing blocks for the sequencer. On official
networks, it is operated by a separate entity from the network operator. Network operators configure their sequencer to
use the official validator endpoint rather than running their own validator for that network.

For unofficial or private networks, the validator is an internal service and should not be exposed publicly.

## Start

```bash
miden-validator start \
  --listen 0.0.0.0:50101 \
  --data-directory validator-data
```

For local development, the validator can use its default insecure development key. Production deployments should
configure validator signing explicitly, either with a local key or with KMS-backed signing.

Use `miden-validator start --help` for the complete current option list.
