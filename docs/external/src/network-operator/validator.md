---
title: "Validator"
sidebar_position: 5
---

# Validator

The validator provides independent verification of Miden blocks before they can be committed. On official networks, it
is operated by a separate entity from the network operator. Network operators configure their sequencer to use the
official validator endpoint rather than running their own validator for that network.

For unofficial or private networks, this separation matters less and the validator can be run as an internal service. It
should not be exposed publicly.

Since the validator sees every block before it is committed, it also stores the raw block data for the blocks it
validates and signs. This makes the validator a network data backup that can be used to recover committed block data if
the sequencer or full-node replicas lose data.

The validator is also a temporary training-wheels layer while the proof and VM systems mature. It receives the private
inputs needed to independently check proposed blocks, which gives the network another place to detect bugs before a
block is committed. Those inputs arrive encrypted against the shared transaction encryption key, so the validator is the
only component that can read them, and submissions that are not encrypted are rejected.

## Key Rotation

Each block header includes the validator key that must be used for the next block. Because the current validator signs
the block header, this next-key commitment is authenticated by the existing validator key. This makes validator key
rotation safe: the network can verify that the next validator key was authorized by the validator that signed the
current block.

## Storage Key Setup

The DKG creates the storage key used to re-encrypt validated private inputs. Run one ceremony for the validator set
committed in genesis. Participant indexes follow the order of validator signing keys in the genesis block.

The threshold is network policy. A threshold of `t` lets any `t` validators decrypt a stored record; fewer validators
cannot. Choose it from the network's confidentiality and availability needs before the ceremony starts.

This flow supports initial storage-key bootstrap only. The validator loads one storage-key epoch. Rotation, creating new
shares, and validator-set changes are not yet supported. Keep each operator bundle available for as long as records from
its epoch may need to be decrypted.

For the normal ceremony, one operator starts the durable Iroh bulletin board:

```bash
miden-validator dkg board \
  --data-directory storage-key-board \
  --genesis genesis.dat \
  --threshold 2 \
  --epoch <32-byte-hex-epoch> \
  --ticket-output storage-key-board-ticket
```

The command writes one board ticket. It contains the board's Iroh address, a read-only document capability, and a bearer
secret for bounded uploads. It contains no private DKG share. Send the file to each genesis validator through the
authenticated bootstrap channel. Anyone with the ticket can read ceremony artifacts and fill empty upload slots, so do
not publish it. Keep the board running until every validator reports ceremony completion, then stop it with Ctrl-C.

Each validator then runs the full ceremony with its own signing key and private work directory:

```bash
miden-validator dkg run \
  --board-file <board-ticket-file> \
  --genesis genesis.dat \
  --signing-key.kms-id <validator-kms-key-id> \
  --work-directory storage-key-work \
  --output-directory storage-key
```

Both commands can restart with the same data and work directories. Give `--ticket-output` a new path when restarting the
board because it will not overwrite a ticket file. The board prepares the common files after all signed registrations
arrive. Each validator checks every artifact, writes its own storage key bundle, and confirms that all validators
produced the same public output. A board directory from an older format cannot be reopened; start that ceremony again in
a new directory.

The commands below provide a manual recovery path. First, each operator creates a DKG identity for the agreed storage-key
epoch and sends `registration.toml` to the coordinator. The registration proves ownership of the DKG identity secret.
The signing key must match one key in genesis. Use `--signing-key.hex` instead of KMS only for local or private
deployments.

```bash
miden-validator dkg identity \
  --genesis genesis.dat \
  --epoch <32-byte-hex-epoch> \
  --signing-key.kms-id <validator-kms-key-id> \
  --output-directory identity
```

The coordinator collects every registration and prepares one common ceremony directory. The setup coefficient is fixed
by the validator backend. The session ID is derived from genesis, the epoch, the threshold, and the ordered
registrations, so every operator can reproduce the same files.

```bash
miden-validator dkg prepare \
  --genesis genesis.dat \
  --threshold 2 \
  --epoch <32-byte-hex-epoch> \
  --registration validator-1-registration.toml \
  --registration validator-2-registration.toml \
  --registration validator-3-registration.toml \
  --output-directory ceremony
```

Each operator checks the ceremony directory over the authenticated bootstrap channel, then creates its dealings.

```bash
miden-validator dkg deal \
  --genesis genesis.dat \
  --ceremony-directory ceremony \
  --identity-secret identity/identity-secret.wire \
  --output-directory dealing
```

After all dealings are exchanged, every operator signs the same transcript. Repeat both dealing options once per
validator.

```bash
miden-validator dkg accept \
  --genesis genesis.dat \
  --ceremony-directory ceremony \
  --signing-key.kms-id <validator-kms-key-id> \
  --decryption-dealing validator-1-decryption-dealing.wire \
  --decryption-dealing validator-2-decryption-dealing.wire \
  --decryption-dealing validator-3-decryption-dealing.wire \
  --context-dealing validator-1-context-dealing.wire \
  --context-dealing validator-2-context-dealing.wire \
  --context-dealing validator-3-context-dealing.wire \
  --output-directory acceptance
```

Compare `transcript.toml` byte for byte across all operators. Collect one signed `transcript-acceptance.toml` from each
operator. Each operator can then create and validate its own startup bundle.

```bash
miden-validator dkg finalize \
  --genesis genesis.dat \
  --ceremony-directory ceremony \
  --identity-secret identity/identity-secret.wire \
  --private-state dealing/private-state.wire \
  --decryption-dealing validator-1-decryption-dealing.wire \
  --decryption-dealing validator-2-decryption-dealing.wire \
  --decryption-dealing validator-3-decryption-dealing.wire \
  --context-dealing validator-1-context-dealing.wire \
  --context-dealing validator-2-context-dealing.wire \
  --context-dealing validator-3-context-dealing.wire \
  --transcript transcript.toml \
  --transcript-acceptance validator-1-transcript-acceptance.toml \
  --transcript-acceptance validator-2-transcript-acceptance.toml \
  --transcript-acceptance validator-3-transcript-acceptance.toml \
  --output-directory storage-key

miden-validator dkg validate \
  --genesis genesis.dat \
  --ceremony-directory ceremony \
  --validator-public-key <validator-public-key-hex> \
  --bundle-directory storage-key
```

The files have these handling rules:

| Files                                                                  | Handling                                                     |
| ---------------------------------------------------------------------- | ------------------------------------------------------------ |
| `registration.toml`, `manifest.toml`, and both DKG configuration files | Public; send through an authenticated channel.               |
| Both dealing files, `transcript.toml`, and transcript acceptances      | Public; send through an authenticated channel.               |
| `identity-secret.wire` and `private-state.wire`                        | Private to one operator; never send.                         |
| `epoch.hex`, `setup-context.wire`, and `public-key-set.wire`           | Public final output; all operators must get identical bytes. |
| `secret-share.wire`                                                    | Private final output; each operator gets a different share.  |

Every operator must confirm matching public output hashes before activation. Once the final bundle is secured,
`identity-secret.wire` and `private-state.wire` are no longer needed. A failed ceremony cannot resume with a partial or
changed participant set; start a new ceremony instead.

## Start

```bash
miden-validator start \
  --listen 0.0.0.0:50101 \
  --data-directory validator-data \
  --signing-key.kms-id <validator-kms-key-id> \
  --encryption-key.kms-ciphertext <encryption-key-ciphertext-base64> \
  --storage-key.epoch <32-byte-hex-epoch> \
  --storage-key.setup-context <setup-context-file> \
  --storage-key.public-key-set <public-key-set-file> \
  --storage-key.secret-share <secret-share-file>
```

A signing key is required — the validator has no default key. Pass either a hex-encoded secret (`--signing-key.hex`) or
a KMS key ID (`--signing-key.kms-id`). For local development, `miden-validator keygen` generates a fresh key-pair;
production deployments should use KMS-backed signing.

In addition to its signing key, every validator holds the shared transaction encryption key, configured with
`--encryption-key.hex` or `MIDEN_VALIDATOR_ENCRYPTION_KEY` (`keygen` generates one alongside the signing key-pair).
Unlike the signing key, this value must be identical across every validator in the set.

Production deployments should not pass the secret in plaintext. Instead, wrap it with a symmetric AWS KMS key
(`aws kms encrypt`) and pass the resulting base64 ciphertext blob unchanged via `--encryption-key.kms-ciphertext` or
`MIDEN_VALIDATOR_ENCRYPTION_KEY_KMS_CIPHERTEXT`. The validator recovers the key material at startup with `kms:Decrypt`,
so its AWS identity needs that permission on the wrapping key. Note that, unlike KMS-backed signing, the decrypted
encryption key is held in validator memory: AWS KMS cannot perform X25519 key agreement itself, so envelope encryption
is the supported provisioning path.

Each validator must run inside its trusted execution environment. If transaction proving uses a remote prover, that
prover also receives the plaintext inputs and must run inside the same trusted boundary.

The files contain canonical wire bytes. Every validator uses the same setup context and public key set, but uses its own
secret share. The validator will not start if any storage key option is missing or the key material is invalid. After
validation, it stores only the transaction ID and the threshold-encrypted record. It does not store the client
ciphertext.

Use `miden-validator start --help` for the complete current option list.
