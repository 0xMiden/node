---
title: "Recovery"
sidebar_position: 10
---

# Recovery

Recovery restores missing committed block data to a node from the validator's block backup. It is used when promoting a
full node to sequencer after the active sequencer is lost, and the promotion target is missing committed blocks.

This complements the [Sequencer Failover](/network-operator/sequencer) flow. Full nodes replicate the sequencer
asynchronously, so a node promoted to sequencer can be behind the committed chain tip. The
[Validator](/network-operator/validator) retains the raw block data for every block it signed, which lets it serve those
missing blocks back to the promotion target.

## When to recover

Recover when both of the following hold:

- The active sequencer is lost or being replaced, and a full node is being promoted to take its place.
- The promotion target is behind the committed chain tip and cannot catch up from another in-sync source.

If the promotion target is already in sync with the committed chain tip, recovery is unnecessary; promote it directly.

## What recovery does

The `miden-node recover` command streams the validator's signed blocks into the node's local storage, starting from the
node's current committed tip and stopping once it reaches the validator's chain tip. It then exits.

Recovered blocks are signed but **carry no proofs** — the validator backs up block data, not block proofs. These blocks
must be imported or re-proven separately as part of recovery before the node resumes block production as a sequencer.

## Procedure

1. Stop the sequencer, if it is not down already.
2. Stop the full node being promoted.
3. Run recovery against the validator, pointed at the promotion target's data directory:

   ```bash
   miden-node recover \
     --data-directory node-data \
     --validator.url http://validator:50101
   ```

   The command applies blocks up to the validator's chain tip and exits. If the node is already at the validator's chain
   tip, it reports that there is nothing to recover and exits successfully.

4. Commission proofs for the recovered blocks.
5. Restart the node as a sequencer. See [Sequencer](/network-operator/sequencer).

## Common Configuration

| Option             | Purpose                                               |
| ------------------ | ----------------------------------------------------- |
| `--data-directory` | Local data storage of the node being recovered.       |
| `--validator.url`  | Internal validator service URL to stream blocks from. |

Use `miden-node recover --help` for the complete current option list.
