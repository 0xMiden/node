---
title: "Recovery"
sidebar_position: 11
---

# Recovery

Recovery restores committed blocks and the inputs needed to prove them from validator backups after sequencer loss. Use
it before promoting a full node, even when that node has the latest committed block: ordinary replication does not copy
proving inputs, and some committed blocks may not yet have proofs.

## Prerequisites

Upgrade and migrate validators before relying on input recovery. Only blocks signed after that upgrade have retained
inputs. Rehearse recovery with newly signed blocks before declaring the deployment recoverable. Older missing inputs
still require an original sequencer copy or a surviving source of the corresponding proofs.

The replacement must have an initialized data directory for the same network. Supply the full validator set, with each
validator available and retaining its signing history. Recovery checks signatures and stops at the smallest validator
tip; coordinate with validator operators if their tips differ. Recovery cannot reconcile divergent chains. Keep the old
sequencer fenced throughout recovery and promotion so it cannot resume block production.

## Procedure

1. Stop and fence the old sequencer. Stop the promotion target before accessing its data directory.
2. Choose one of the following completion modes and run recovery against every validator.

   **Restore inputs only**, when the existing `fee-collector.mac` survives:

   ```bash
   miden-node recover \
     --data-directory node-data \
     --validator.url http://validator-0:50101 \
     --validator.url http://validator-1:50101 \
     --validator.url http://validator-2:50101
   ```

   Successful completion reports that inputs are ready for proving. Every locally unproven block has usable inputs,
   including blocks already present before recovery. This does not guarantee proof availability. Copy the existing
   `fee-collector.mac` into the replacement data directory; the normal sequencer scheduler can then prove the backlog.

   **Restore and prove**, when the collector file is lost or proofs are required before promotion:

   ```bash
   miden-node recover \
     --data-directory node-data \
     --validator.url http://validator-0:50101 \
     --validator.url http://validator-1:50101 \
     --validator.url http://validator-2:50101 \
     --prove \
     --block-prover.url http://block-prover:50051
   ```

   Omit `--block-prover.url` to prove locally. The URL alone does not enable proving; `--prove` is required. This mode
   creates no blocks and needs no collector file. Successful completion reports that recovery proving is complete: the
   recovered committed prefix has proofs, and the proven and committed tips match.

3. If the collector file was lost, wait for `--prove` to complete, then create and deploy a replacement collector using
   [Fee Collection](./sequencer.md#fee-collection). Keep the node stopped until deployment completes. If the existing
   collector was restored, it does not need deployment again.
4. Restart the replacement as a [sequencer](./sequencer.md), keeping the old sequencer fenced.

## Failure and retry

A failed or interrupted command preserves completed block, input, and proof writes. Resolve the reported error and rerun
the same command against the same data directory. Recovery checks existing inputs and repairs missing or corrupt files
without reapplying committed blocks. Proving resumes after the last persisted proof.

If recovery reports a historical block without usable inputs, restore its original inputs or synchronize its proof from
a surviving node before retrying. Migrating a validator does not reconstruct inputs for old blocks. Do not promote a
node with an uncovered unproven gap or bypass the proof requirement for replacement collector deployment.
