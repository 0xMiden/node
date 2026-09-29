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

Only method-specific failures with documented additional codes set the details byte. Other errors, including request
limits, unsupported content negotiation, missing genesis data, and failed proof checks, can return gRPC statuses without
a Miden error detail code. The error message remains applicable in all cases. Do not match on the error message because
it can change.

If you are missing specific error information that could be useful, please open an issue in the
[Node Repository](https://github.com/0xMiden/node).

## Method-Specific Error Codes

Codes are specific to each method. Code `0` identifies an internal failure with the `INTERNAL` gRPC status. This code
applies to all methods in the table, `GetBlockByNumber`, and `GetBlockHeaderByNumber`.

| Method                                       | Error                   | Value | gRPC status        |
| -------------------------------------------- | ----------------------- | ----- | ------------------ |
| **`GetAccount`**                             | `DeserializationFailed` | `1`   | `INVALID_ARGUMENT` |
|                                              | `AccountNotFound`       | `2`   | `INVALID_ARGUMENT` |
|                                              | `AccountNotPublic`      | `3`   | `INVALID_ARGUMENT` |
|                                              | `UnknownBlock`          | `4`   | `INVALID_ARGUMENT` |
|                                              | `BlockPruned`           | `5`   | `INVALID_ARGUMENT` |
|                                              | `StorageSlotNotFound`   | `6`   | `INVALID_ARGUMENT` |
|                                              | `StorageSlotNotMap`     | `7`   | `INVALID_ARGUMENT` |
|                                              |                         |       |                    |
| **`GetNotesById`**                           | `DeserializationFailed` | `1`   | `INVALID_ARGUMENT` |
|                                              |                         |       |                    |
| **`GetNoteScriptByRoot`**                    | `DeserializationFailed` | `1`   | `INVALID_ARGUMENT` |
|                                              |                         |       |                    |
| **`SyncNotes`**                              | `InvalidBlockRange`     | `1`   | `INVALID_ARGUMENT` |
|                                              | `FutureBlock`           | `2`   | `INVALID_ARGUMENT` |
|                                              | `DeserializationFailed` | `3`   | `INVALID_ARGUMENT` |
|                                              |                         |       |                    |
| **`SyncNullifiers`**                         | `InvalidBlockRange`     | `1`   | `INVALID_ARGUMENT` |
|                                              | `InvalidPrefixLength`   | `2`   | `INVALID_ARGUMENT` |
|                                              | `DeserializationFailed` | `3`   | `INVALID_ARGUMENT` |
|                                              | `FutureBlock`           | `4`   | `INVALID_ARGUMENT` |
|                                              |                         |       |                    |
| **`SyncAccountVault`**                       | `InvalidBlockRange`     | `1`   | `INVALID_ARGUMENT` |
|                                              | `DeserializationFailed` | `2`   | `INVALID_ARGUMENT` |
|                                              | `AccountNotPublic`      | `3`   | `INVALID_ARGUMENT` |
|                                              | `FutureBlock`           | `4`   | `INVALID_ARGUMENT` |
|                                              |                         |       |                    |
| **`SyncAccountStorageMaps`**                 | `InvalidBlockRange`     | `1`   | `INVALID_ARGUMENT` |
|                                              | `DeserializationFailed` | `2`   | `INVALID_ARGUMENT` |
|                                              | `AccountNotPublic`      | `4`   | `INVALID_ARGUMENT` |
|                                              | `FutureBlock`           | `5`   | `INVALID_ARGUMENT` |
|                                              |                         |       |                    |
| **`SyncTransactions`**                       | `InvalidBlockRange`     | `1`   | `INVALID_ARGUMENT` |
|                                              | `DeserializationFailed` | `2`   | `INVALID_ARGUMENT` |
|                                              | `FutureBlock`           | `5`   | `INVALID_ARGUMENT` |
|                                              |                         |       |                    |
| **`SyncChainMmr`**                           | `FutureBlock`           | `2`   | `INVALID_ARGUMENT` |
|                                              |                         |       |                    |
| **`SubmitProvenTx` / `SubmitProvenTxBatch`** | `Internal`              | `0`   | `INTERNAL`         |
|                                              | `Expired`               | `1`   | `INVALID_ARGUMENT` |
|                                              | `StateConflict`         | `2`   | `INVALID_ARGUMENT` |
|                                              | `CapacityExceeded`      | `3`   | `INVALID_ARGUMENT` |
|                                              | `MissingFee`            | `4`   | `INVALID_ARGUMENT` |
|                                              | `InvalidFeeAsset`       | `6`   | `INVALID_ARGUMENT` |
|                                              | `AuthenticationFailed`  | `8`   | `INVALID_ARGUMENT` |

`InvalidBlockRange` means that the start of the range exceeds its end. `SyncNotes`, `SyncNullifiers`,
`SyncAccountVault`, `SyncAccountStorageMaps`, and `SyncTransactions` return `FutureBlock` when the range extends beyond
the chain tip. `SyncChainMmr` returns `FutureBlock` when the client height exceeds the requested chain tip.
`SyncNullifiers` returns `DeserializationFailed` for a prefix that exceeds 16 bits.

`GetAccount` returns `StorageSlotNotFound` when a storage map request names a slot that the account does not have at
the requested block. It returns `StorageSlotNotMap` when the named slot is a value slot.

Unused values remain reserved. Clients must accept unknown detail codes and fall back to the gRPC status code.

## Transaction Submission Errors

`SubmitProvenTx` and `SubmitProvenTxBatch` share the submission codes in the table above. These codes identify failures
during submission validation or in the sequencer's mempool.

`Expired` means the transaction or batch has expired, or will expire too soon for the sequencer to consider accepting
it.

`StateConflict` means the transaction conflicts with the chain or mempool state. It can represent spent nullifiers,
duplicate output notes, missing unauthenticated input notes, or an account initial commitment mismatch. Use the status
message for the specific conflict, and use the detail byte when a client needs stable branching between broad submission
failure classes.

`CapacityExceeded` means the mempool capacity has been exhausted and is under load.

`AuthenticationFailed` means the transaction failed authentication against the chain state. For example, an input
nullifier already exists. The status message includes the cause.

`MissingFee` means that a standalone transaction submitted through `SubmitProvenTx` does not contain an output note with
the `TX_FEE` script when the reference block's verification base fee is nonzero. A transaction can omit the fee note
when that base fee is zero. Each fee note must contain exactly one native asset, as specified by the reference block's
protocol configuration, even when fees are zero. `InvalidFeeAsset` means that a fee note does not meet this asset
requirement. The internal `SubmitAuthenticatedTx` endpoint applies the same checks. Transactions within user-submitted
batches are exempt because those batches handle their own fee collection. These checks do not establish that the fee
amount is sufficient. A fee note can contain a zero-valued native asset when the required fee is zero.

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
