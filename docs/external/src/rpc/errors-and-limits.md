---
title: "Errors and Limits"
sidebar_position: 3
---

# Errors and Limits

The Miden RPC API uses standard gRPC status codes. Individual methods may also return structured details defined by the
protobuf schema or encoded by the server implementation.

## Request Limits

Use `GetLimits` to discover method-specific request limits before sending large sync requests. Methods such as
`SyncNotes`, `SyncNullifiers`, and `GetNotesById` may reject requests that exceed the configured limit. Split larger
requests into smaller batches.

## Content Negotiation

The RPC server checks the `Accept` header for Miden-specific media parameters:

```text
application/vnd.miden; version=<semver>; genesis=<genesis-commitment>
```

Both parameters are optional for read requests. Write requests, including `SubmitProvenTx` and `SubmitProvenTxBatch`,
require the `genesis` parameter so the client explicitly targets the intended network.

The server accepts compatible major/minor RPC versions. Stable versions allow patch flexibility. Pre-release versions
must match the pre-release label and patch version expected by the server.

## Common Status Codes

| Status               | Typical meaning                                                                                   |
| -------------------- | ------------------------------------------------------------------------------------------------- |
| `INVALID_ARGUMENT`   | The request is malformed, exceeds limits, targets an unknown block, or fails content negotiation. |
| `NOT_FOUND`          | The requested resource is not known to the node or supporting service.                            |
| `RESOURCE_EXHAUSTED` | The request exceeded a configured limit or rate limit.                                            |
| `UNAVAILABLE`        | A required upstream or internal service is unavailable.                                           |
| `DATA_LOSS`          | A subscription consumer lagged too far behind and should reconnect from local state.              |
| `INTERNAL`           | The server encountered an unexpected internal failure.                                            |
