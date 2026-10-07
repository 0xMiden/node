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

The distributed key generation (DKG) ceremony creates the key material used to protect stored private inputs. Every
validator must participate, and each produces its own private bundle for starting the validator service.

The ceremony assumes all validators are trusted to follow the protocol. It is not designed to handle Byzantine
participants or equivocation, where a validator sends conflicting messages to different peers. Transcript comparisons
abort on detected mismatches; they do not provide Byzantine fault tolerance.

The threshold determines how many validators must cooperate to decrypt stored data, not how many must join the ceremony.
A threshold of `t` lets any `t` validators decrypt a stored record; fewer validators cannot.

This procedure supports initial storage-key setup only. Storage-key rotation and validator-set changes are not yet
supported. Keep each validator's bundle for as long as stored records may need to be decrypted.

Before starting, all operators must agree on the participating validators, threshold, and storage-key epoch. Exchange
validator public keys through a trusted channel. The ceremony uses these keys to authenticate peers and does not require
a genesis block. For initial network setup, use the same validator keys as the network's genesis configuration.

Generate a persistent Iroh endpoint identity for each validator:

```bash
miden-validator dkg generate-endpoint --output-file endpoint.secret
```

Keep the endpoint secret private and share the printed public endpoint ID with the other operators. Reuse the endpoint
secret across ceremonies.

Run the following command for each validator using its own signing key. Repeat `--peer` once per other validator, with
that validator's public key followed by its endpoint ID. Do not include the local validator. This example opts into n0's
public Iroh relays and address discovery, so no peer socket addresses are needed. The public relays are intended for
development and testing; do not rely on them for guaranteed production availability.

```bash
miden-validator dkg participate \
  --endpoint-secret endpoint.secret \
  --enable-public-relay \
  --peer <other-validator-public-key> <other-validator-endpoint-id> \
  --peer <another-validator-public-key> <another-validator-endpoint-id> \
  --threshold 2 \
  --epoch <32-byte-hex-epoch> \
  --signing-key.kms-id <validator-kms-key-id> \
  --output-file storage-key.bundle
```

For a local or private network with direct UDP connectivity, omit `--enable-public-relay`. Set a local listening address
with `--bind-address <IP:PORT>` and supply each peer as `--peer <PUBLIC_KEY> <ENDPOINT_ID>@<IP:PORT>`. For example,
local participants can listen on `127.0.0.1:9001` and `127.0.0.1:9002`. This mode uses no public relay or address
discovery and works without internet access. IPv6 peer addresses use brackets, such as `<ENDPOINT_ID>@[::1]:9002`.

Validators can start at different times; the ceremony waits for all participants to join. The entire ceremony must
finish within `--timeout`, which defaults to `30m`. For a single validator, omit `--peer` and use `--threshold 1`.

The command reports success only after every validator confirms it has saved its bundle. Only then is the bundle safe to
use. Each bundle belongs to one validator and must remain private.

A failed or timed-out ceremony cannot resume. Do not use any bundles from that attempt. Restart the ceremony with all
participants and new output paths, reusing the endpoint secrets.

## Start

Pass the bundle produced for this validator using `--storage-key.file <FILE>` or `MIDEN_VALIDATOR_STORAGE_KEY_FILE`. The
validator will not start without a valid bundle. To use a text-only secret store, base64-encode the bundle for upload
and decode it back to the original bytes before loading it.

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

After validation, the validator stores only the transaction ID and the threshold-encrypted record. It does not store the
client ciphertext.

Use `miden-validator start --help` for the complete current option list.
