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

Validators compare ceremony transcript commitments and abort on a mismatch, including when a participant sends
conflicting contributions to different peers (equivocation).

Completion requires every configured validator. Any participant can prevent completion by withholding messages or
sending conflicting contributions. Run the ceremony with validators you trust to cooperate; it cannot exclude a faulty
participant and continue with a smaller set.

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

## Administration API

The validator can serve a private JSON administration API. Operators use it to find the stored records of validated
transactions and to request the decryption shares that open them. The listener is disabled by default. Configure its
address to enable it:

```bash
--admin.listen 127.0.0.1:50102
```

The corresponding environment variable is `MIDEN_VALIDATOR_ADMIN_LISTEN`. The API does not authenticate requests.
Enforce authentication and authorization externally, and prevent direct access to this listener. Keep it on an isolated
operator network behind an authenticated proxy or gateway. The listener serves HTTP; terminate TLS at the proxy for
remote access.

| Method | Path                                      | Request                                               | Result                                                                                          |
| ------ | ----------------------------------------- | ----------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| `GET`  | `/admin/v1/transactions`                  | Query parameters                                      | One page of committed transactions and a `pagination` object.                                   |
| `GET`  | `/admin/v1/transactions/{transaction_id}` | None                                                  | The stored record of one validated transaction, or `404` if this validator did not validate it. |
| `POST` | `/admin/v1/decryption-share`              | `{"ciphertext":"<hex>","decryption_context":"<hex>"}` | `{"decryption_share":"<hex>"}`                                                                  |

Byte values are hexadecimal strings without a `0x` prefix. Errors from request handlers have the form
`{"error":"<message>"}`: invalid parameter values return `400`, and internal failures return `500`. Requests rejected
before reaching a handler return a plain-text error body. These include malformed query parameters or malformed JSON
(`400`), a JSON body with the wrong shape (`422`), and a missing or unsupported JSON content type (`415`).

### List Transactions

The listing returns the transactions that a signed block includes, in the order of the chain: by block number, then by
index within the block. A validated transaction that is not in a signed block is not listed. A transaction that a block
included before the validator database recorded block positions is also not listed. Use the single-transaction endpoint
to read those records.

| Parameter         | Default     | Description                                                                                       |
| ----------------- | ----------- | ------------------------------------------------------------------------------------------------- |
| `block_from`      | First block | First block to list, inclusive.                                                                   |
| `tx_index_from`   | `0`         | First index to list within `block_from`. Requires `block_from`.                                   |
| `block_to`        | None        | Last block to list, inclusive.                                                                    |
| `limit`           | `100`       | Maximum number of transactions in the page. At most `1000`, or `100` with `include_records=true`. |
| `include_records` | `false`     | Adds the stored record to each transaction.                                                       |

Each transaction has `transaction_id`, `block_num`, `block_tx_index`, `key_epoch`, and `setup_context_id`. With
`include_records=true`, it also has a `record` object with `final_ciphertext`, `cipher_nonce`, `encrypted_record_key`,
and `decryption_context`.

The `pagination` object has `chain_tip`, `block_num`, and `block_tx_index`. `chain_tip` is the highest block that this
validator has signed. The transactions, optional records, and chain tip in each response describe the same database
snapshot. `block_num` and `block_tx_index` are the position of the last transaction in the page. To read the next page,
repeat the request with `block_from` set to `block_num` and `tx_index_from` set to `block_tx_index + 1`. Both values are
`null` when the page is empty, which ends the sweep.

```bash
curl 'http://127.0.0.1:50102/admin/v1/transactions?block_from=1&limit=2'
```

```json
{
  "transactions": [
    {
      "transaction_id": "<hex>",
      "block_num": 1,
      "block_tx_index": 0,
      "key_epoch": "<hex>",
      "setup_context_id": "<hex>"
    },
    {
      "transaction_id": "<hex>",
      "block_num": 1,
      "block_tx_index": 1,
      "key_epoch": "<hex>",
      "setup_context_id": "<hex>"
    }
  ],
  "pagination": { "chain_tip": 12, "block_num": 1, "block_tx_index": 1 }
}
```

The block at `chain_tip` can still be replaced, and the replacement can include other transactions. To read only final
transactions, set `block_to` below `chain_tip`, or read the tip block again from index `0` after the tip advances.

### Get a Transaction

The response has `transaction_id`, `final_ciphertext`, `cipher_nonce`, `encrypted_record_key`, and `decryption_context`
for one validated transaction. The `transaction_id` in the path is 64 hexadecimal characters. This endpoint also serves
a transaction that is not in a signed block.

### Issue a Decryption Share

To open a record, collect decryption shares from a threshold of validators. Each validator stores its own ciphertext for
a transaction, and a share over the ciphertext of one validator does not combine with a share over the ciphertext of
another validator. Read the record from one validator, then send the `encrypted_record_key` of that record as
`ciphertext`, with its `decryption_context`, to each validator. A validator therefore issues a share over a ciphertext
that it does not store.

A validator issues a share only when the `decryption_context` names a transaction that it validated. Otherwise it
returns `404`. It returns `400` when the context is not a canonical record context, or when the context names a key
epoch other than the `--storage-key.epoch` of the validator.
