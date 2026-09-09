---
title: "Recovery"
sidebar_position: 11
---

# Recovery

Recovery restores missing committed block data to a node from the validators' block backups. It is used when promoting a
full node to sequencer after the active sequencer is lost, and the promotion target is missing committed blocks.

This complements the [Sequencer Failover](/network-operator/sequencer) flow. Full nodes replicate the sequencer state
asynchronously, so there is no guarantee that the node is fully up to date if the sequencer fails. These missing data
can always be recovered from the validators because every validator has to sign every block before it can be committed.

## When to recover

Recover when both of the following hold:

- The active sequencer is lost or being replaced, and a full node is being promoted to take its place.
- The promotion target is behind the committed chain tip and cannot catch up from another in-sync source.

## What recovery does

The `miden-node recover` command streams each validator's signed blocks into the node's local storage, starting from the
node's current committed tip and stopping once it reaches the smallest of the validators' chain tips. It then exits.

Each validator's block backup carries only that validator's own signature, so the command must be pointed at the full
validator set: for every block it collects one signature per validator, orders them against the validator set committed
to by the parent block's header, and verifies the reconstructed block before applying it.

Recovered blocks are signed but **carry no proofs** — validators back up block data, not block proofs. These blocks must
be imported or re-proven separately as part of recovery before the node resumes block production as a sequencer.

## Procedure

1. Stop the sequencer, if it is not down already.
2. Stop the full node being promoted.
3. Run recovery against the full validator set, pointed at the promotion target's data directory:

   ```bash
   miden-node recover \
     --data-directory node-data \
     --validator.url http://validator-0:50101 \
     --validator.url http://validator-1:50101 \
     --validator.url http://validator-2:50101
   ```

   The command applies blocks up to the validators' chain tip and exits. If the node is already at the validators' chain
   tip, it reports that there is nothing to recover and exits successfully.

4. Commission proofs for the recovered blocks.
5. Restart the node as a sequencer. See [Sequencer](/network-operator/sequencer).
