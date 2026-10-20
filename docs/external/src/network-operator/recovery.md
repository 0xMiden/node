---
title: "Recovery"
sidebar_position: 11
---

# Recovery

Recovery prepares a full node to replace a lost sequencer by restoring committed blocks and the data needed to generate
their proofs. Run recovery before promoting the replacement, even if it has the latest committed block. Full-node
replication does not copy proving inputs, so the replacement may have blocks it cannot yet prove.

## Prerequisites

Before relying on validator backups for failover, coordinate with validator operators to rehearse this procedure and
verify that the backups contain the blocks and proving inputs the replacement needs.

Validators running v0.17.6 or earlier did not retain proving inputs. Blocks signed by those versions therefore need
another source of inputs or proofs. Upgrading and migrating validator storage preserves the blocks but does not
reconstruct their missing inputs.

For recovery, you need:

- An initialized data directory for the same network on the replacement node.
- Reachable endpoints for every validator in the set, with their signing histories intact. Recovery requires all
  validators' signatures, although one retained copy of a block's proving inputs is sufficient.
- Proving inputs for every unproven block, either in the replacement's local storage or in validator backups. If neither
  has usable inputs, you need the original sequencer inputs or a surviving source of that block's proof.

Coordinate with validator operators if their latest signed block heights differ. Recovery uses the lowest height as its
target and cannot recover newer blocks until every validator can supply its signature. It verifies recovered blocks and
proving inputs automatically and rejects blocks that conflict with the replacement's local chain.

## Choose when to prove

Recovery restores blocks and proving inputs by default. If the existing `fee-collector.mac` file is available, you can
restore it and let the replacement sequencer prove the outstanding blocks after startup.

Use `--prove` to generate the missing proofs before starting the replacement. This is required if the collector file is
lost: deploying a new collector requires all committed blocks to have proofs. Recovery with `--prove` does not need a
collector file or produce new blocks. It proves locally unless you supply `--block-prover.url`; that URL only selects a
prover and does not enable proving by itself.

## Procedure

1. Stop the old sequencer and prevent it from restarting or producing blocks throughout recovery and promotion. Stop the
   replacement node before running commands against its data directory.
2. Run one of the following commands on the replacement. Replace `node-data` with its data directory and supply one
   `--validator.url` for each validator in your deployment.

   To restore blocks and proving inputs:

   ```bash
   miden-node recover \
     --data-directory node-data \
     --validator.url http://validator-0:50101 \
     --validator.url http://validator-1:50101 \
     --validator.url http://validator-2:50101
   ```

   A successful exit reports `Recovered inputs are ready for proving`. Every locally committed, unproven block then has
   usable inputs, including blocks present before recovery. This mode does not generate proofs; the sequencer or a later
   `recover --prove` invocation must generate any outstanding proofs.

   To restore blocks and inputs, then generate proofs using a remote prover:

   ```bash
   miden-node recover \
     --data-directory node-data \
     --validator.url http://validator-0:50101 \
     --validator.url http://validator-1:50101 \
     --validator.url http://validator-2:50101 \
     --prove \
     --block-prover.url http://block-prover:50051
   ```

   Omit `--block-prover.url` to prove locally. A successful exit reports `Recovery proving complete`. All locally
   committed blocks then have proofs, and the reported proven and committed block heights match.

3. Restore the fee collector account. If `fee-collector.mac` survives, copy it into the replacement data directory. It
   contains the collector's signing key and is not replicated with chain state. The existing account is already deployed
   and does not need deployment again. If the file was lost, wait for `--prove` to succeed, then create and deploy a new
   account using [Fee Collection](./sequencer.md#fee-collection). Keep the replacement node stopped until deployment
   completes.
4. Start the replacement as a [sequencer](./sequencer.md#start). Keep the old sequencer disabled so only the replacement
   produces blocks.

## Failure and retry

A failed or interrupted command preserves completed writes. Keep both nodes stopped, resolve the reported error, and
rerun the same command against the replacement's data directory. Recovery preserves valid local inputs and repairs
missing or corrupt inputs from validator backups without reapplying committed blocks. Proving resumes after the last
stored proof.

If inputs are unavailable for an unproven block, restore its original sequencer inputs or synchronize its proof from a
surviving node, stop the replacement, and retry. If a validator is unavailable or behind the recovery target you need,
coordinate with its operator before retrying. For a chain conflict, resolve which data directory belongs to the intended
chain before continuing; recovery does not replace conflicting committed blocks.

Promote the replacement only after recovery succeeds and its collector account is ready. The collector deployment
command also checks that every committed block has a proof before deploying a new account.
