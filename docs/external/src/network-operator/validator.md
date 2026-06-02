---
title: "Validator"
sidebar_position: 4
---

# Validator

The validator verifies submitted transactions and proposed blocks before signing blocks for the
sequencer. It is an internal service and should not be exposed publicly.

## Start

```sh
miden-validator start \
  --listen 0.0.0.0:50101 \
  --data-directory validator-data
```

For local development, the validator can use its default insecure development key. Production
deployments should configure validator signing explicitly, either with a local key or with
KMS-backed signing.

Use `miden-validator start --help` for the complete current option list.
