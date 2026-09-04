---
title: "Errors and Limits"
sidebar_position: 3
---

# Errors and Limits

The Miden RPC API uses standard gRPC status codes. Individual methods may also return structured details defined by the
protobuf schema or encoded by the server implementation.

## Structured Error Details

Some methods encode a method-specific error enum in addition to the conventional gRPC error code. This error enum is
encoded in the gRPC status `details` field, allowing clients to branch on more detailed error conditions.

When present, the detail payload contains the method-specific error code as a single raw byte. This byte can be
interpreted as per the per-method tables below.

```text
if status.details is not empty:
    error_code = status.details[0]
    # Interpret error_code using the failed method's table.
else:
    # Fall back to the gRPC status code and message.
```

Only method-specific failures with documented additional codes set the details byte. Other validation errors, including
malformed requests, unsupported content negotiation, missing genesis data, and failed proof checks, return ordinary gRPC
statuses without a Miden error detail code. The error message remains applicable in all cases, but should be considered
unstable and it is not recommended to match on it.

If you are missing specific error information that could be useful, please open an issue in the
[Node Repository](https://github.com/0xMiden/node).

## Transaction Submission Errors

`SubmitProvenTx` and `SubmitProvenTxBatch` may return the following detail codes when a transaction or batch is rejected
during submission validation or by the sequencer's mempool.

| Error              | Value | gRPC status        | Meaning                               |
| ------------------ | ----- | ------------------ | ------------------------------------- |
| `Internal`         | `0`   | `INTERNAL`         | Internal submission failure           |
| `Expired`          | `1`   | `INVALID_ARGUMENT` | Transaction expired                   |
| `StateConflict`    | `2`   | `INVALID_ARGUMENT` | State conflict                        |
| `CapacityExceeded` | `3`   | `INVALID_ARGUMENT` | Mempool capacity exceeded             |
| `MissingFee`       | `4`   | `INVALID_ARGUMENT` | Transaction has no canonical fee note |

`Expired` means the transaction or batch has expired, or will expire too soon for the sequencer to consider accepting
it.

`StateConflict` is intentionally coarse. It can represent spent nullifiers, duplicate output notes, missing
unauthenticated input notes, or an account initial commitment mismatch. Use the status message for the specific
conflict, and use the detail byte when a client needs stable branching between broad submission failure classes.

`CapacityExceeded` means the mempool capacity has been exhausted and is under load.

`MissingFee` means that a transaction submitted through `SubmitProvenTx` or `SubmitProvenTxBatch` does not contain an
output note with the canonical `TX_FEE` script. This check applies to all submitted transactions. It does not establish
that the fee amount is sufficient. A fee note can contain a zero-valued asset when the required fee is zero.

### Encrypted input errors

Rejections caused by the sealed transaction inputs happen before the mempool, so they carry no Miden detail code and
fall into the ordinary-gRPC-status bucket described above:

- `INVALID_ARGUMENT` when the sealed inputs are absent, empty, or fail to authenticate. Failing to authenticate is
  deliberately indistinguishable between a wrong key, tampered ciphertext, a blob sealed for a different transaction or
  network, and corrupt framing.
- `FAILED_PRECONDITION` when the inputs were sealed against a key the validator does not hold. This is the one case a
  client can act on: re-fetch `GetTransactionEncryptionKey` and seal again. Treat it as non-retryable without
  re-sealing, and back off rather than retrying in a tight loop, since official endpoints may rate limit requests at the
  infrastructure level.

## Request Limits

Use `GetLimits` to discover method-specific request limits before sending large sync requests. Methods such as
`GetAccount`, `SyncNotes`, `SyncNullifiers`, and `GetNotesById` may reject requests that exceed the configured limit.
Split larger requests into smaller batches.

The limits are returned in `json` format as follows:

```json
{
  "endpoints": {
    "GetAccount": { "parameters": { "storage_map_key": 64 } },
    "GetNotesById": { "parameters": { "note_id": 100 } },
    "SyncNotes": { "parameters": { "note_tag": 1000 } },
    "SyncNullifiers": { "parameters": { "nullifier_prefix": 1000 } },
    "SyncTransactions": { "parameters": { "account_id": 1000 } }
  }
}
```

## Content Negotiation

The RPC server checks the `Accept` header for Miden-specific media parameters:

```text
application/vnd.miden; version=<semver>; genesis=<genesis-commitment>
```

Both parameters are optional for read requests. Write requests, including `SubmitProvenTx` and `SubmitProvenTxBatch`,
require the `genesis` parameter so the client explicitly targets the intended network.

The server accepts compatible major/minor RPC versions. Stable versions allow patch flexibility. Pre-release versions
must match the pre-release label and patch version expected by the server.
