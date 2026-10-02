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

The live peer-to-peer DKG creates the storage key used to re-encrypt validated private inputs. Every validator committed
in genesis must participate. Each validator authenticates its peers with their genesis signing keys, exchanges its own
DKG messages with every other participant, and confirms matching transcript and public output commitments.

The threshold is network policy. A threshold of `t` lets any `t` validators decrypt a stored record; fewer validators
cannot. All participants must use the same trusted genesis block, threshold, and storage-key epoch. Participant indexes
follow the sorted validator signing public keys.

This flow supports initial storage-key bootstrap only. The validator loads one storage-key epoch. Rotation, creating new
shares, and validator-set changes are not yet supported. Keep each operator bundle available for as long as records from
its epoch may need to be decrypted.

Generate a persistent Iroh endpoint identity for each validator before the ceremony. Endpoint provisioning does not
depend on genesis:

```bash
miden-validator dkg generate-endpoint --output-file endpoint.secret
```

Keep the secret file private and share the printed public endpoint ID with the other operators. Endpoint IDs identify
connection destinations, not trusted validator identities. Authentication checks ownership of a validator signing key
committed in genesis. Reuse the endpoint secret across ceremonies.

All participants must use the same dedicated Iroh relay.

Run the following command for each validator using its own signing key. Repeat `--peer.endpoint` once per other genesis
validator.

```bash
miden-validator dkg participate \
  --genesis genesis.dat \
  --endpoint-secret endpoint.secret \
  --relay.url https://relay.example.org \
  --peer.endpoint <other-validator-endpoint-id> \
  --peer.endpoint <another-validator-endpoint-id> \
  --threshold 2 \
  --epoch <32-byte-hex-epoch> \
  --signing-key.kms-id <validator-kms-key-id> \
  --output-file storage-key.bundle
```

Validators can start at different times; the ceremony waits for all participants to join. The entire ceremony must
finish within `--timeout`, which defaults to `30m`. For a single validator, omit `--peer.endpoint` and use `--threshold 1`.

Every validator writes its own bundle before confirming completion to its peers. The command reports success only after
every participant confirms persistence with matching session, transcript, and public output commitments. Treat both the
endpoint secret and the bundle as private files, with permissions of `0600`.

A failed or timed-out ceremony cannot resume. Do not activate any bundle left by that attempt. Start a new ceremony with
every participant and a new output path, preserving the endpoint secrets. Ephemeral DKG secrets and nonces are generated
again; operators do not need to select a session ID.

## Start

Pass this validator's completed bundle using `--storage-key.file <FILE>` or `MIDEN_VALIDATOR_STORAGE_KEY_FILE`. The
bundle can live outside the data directory; keep its permissions at `0600`. This versioned binary file contains the
epoch, public setup, public key set, and private share. The ceremony takes `--output-file <FILE>` and needs only an
existing output parent directory, not a bootstrapped validator data directory. Treat the entire file as secret. To store
it in a text-only secret store, base64-encode it for upload and decode it back to the original bytes before loading it.

The DKG command reports success only after every validator announces a persisted bundle with matching session, dealing
transcript, and public output commitments. A failed or timed-out exchange can leave a local bundle on disk. Do not
activate that bundle as the output of a successful ceremony.

```bash
miden-validator start \
  --listen 0.0.0.0:50101 \
  --data-directory validator-data \
  --storage-key.file storage-key.bundle \
  --signing-key.kms-id <validator-kms-key-id> \
  --encryption-key.kms-ciphertext <encryption-key-ciphertext-base64>
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

The bundle contains canonical wire bytes. Every validator uses the same setup context and public key set, but uses its
own secret share. The validator will not start if the bundle file is missing or the key material is invalid. After
validation, it stores only the transaction ID and the threshold-encrypted record. It does not store the client
ciphertext.

Use `miden-validator start --help` for the complete current option list.
