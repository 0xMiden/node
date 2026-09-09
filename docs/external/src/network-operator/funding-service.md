---
title: "Funding Service"
sidebar_position: 8
---

# Funding Service

The funding service sends the chain's native asset to any account that asks for it. It owns one wallet account, which
holds the native asset, and creates a private pay-to-ID note for each request.

A transaction pays its fee in the native asset out of the vault of the account that executes it. Infrastructure that
submits transactions therefore needs a source of that asset. On a network without a public faucet the funding service is
that source, and it gives an operator a single account to keep funded.

## Provision the funding account

The funding account is created at genesis. Add a named wallet to the genesis configuration:

```toml
[[wallet]]
account_type = "public"
assets       = [{ amount = 1_000_000_000_000, symbol = "MIDEN" }]
name         = "funding_service"
```

The name makes `miden-validator genesis` write the account file to `<accounts-directory>/funding_service.mac` instead of
a name derived from the wallet's index, so the service can load it from a fixed path. The account must be public: the
service reads the account's vault and nonce back from the node, which only stores the full state of a public account.

The amount is in base units of the native asset, which has six decimals. The example is one million MIDEN. Size it for
the lifetime of the network: on a development or test network a pre-funded balance large enough to last for years avoids
any manual top-up. Note that the total issuance of all genesis accounts must stay within the native faucet's maximum
supply.

## Start

```bash
miden-funding-service start \
  --listen 0.0.0.0:50401 \
  --rpc.url http://rpc-node:57291 \
  --tx-prover.url http://tx-prover:50051 \
  --account-file /opt/miden-funding-service/funding_service.mac \
  --validator-signing-public-key <validator-signing-public-key>
```

| Option                           | Default      | Purpose                                                                                                                                                                 |
| -------------------------------- | ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--listen`                       | required     | Socket address of the gRPC API.                                                                                                                                         |
| `--rpc.url`                      | required     | The node RPC API the service reads from and submits to.                                                                                                                 |
| `--account-file`                 | required     | Path to the funding account's `.mac` file.                                                                                                                              |
| `--validator-signing-public-key` | required     | Hex-encoded validator signing public key trusted to attest the transaction encryption key. Repeat the flag, or pass a comma separated list, to trust more than one key. |
| `--tx-prover.url`                | none         | Remote transaction prover. Without it the service proves in process.                                                                                                    |
| `--max-amount`                   | `1000000000` | Largest amount one request may ask for, in base units.                                                                                                                  |
| `--max-notes-per-tx`             | `16`         | Largest number of notes one transaction creates. Must not exceed 100.                                                                                                   |
| `--tx-expiration-delta`          | `50`         | Blocks after its reference block at which a funding transaction expires.                                                                                                |
| `--poll-interval`                | `1s`         | How often the service asks the node whether its notes are committed.                                                                                                    |
| `--grpc.timeout`                 | `5m`         | Largest duration allocated to one gRPC request.                                                                                                                         |
| `--rpc.timeout`                  | `10s`        | Timeout of a request to the node.                                                                                                                                       |
| `--tx-prover.timeout`            | `1m`         | Timeout of a request to the remote prover.                                                                                                                              |

A `RequestFunds` call blocks until the note is committed, so `--grpc.timeout` must exceed the proving time plus the
expiration window (`--tx-expiration-delta` multiplied by the chain's block interval). Raise it where proving is slow. A
client must set a matching deadline of its own.

Every option also reads from an environment variable named `MIDEN_FUNDING_<OPTION>`, for example
`MIDEN_FUNDING_ACCOUNT_FILE`.

## API

The service exposes two methods on `funding_service.Api`.

| Method         | Purpose                                                                                                                          |
| -------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `Status`       | Returns the funding account's ID, its balance, the block the service is synchronized to, and the configured maximum amount.      |
| `RequestFunds` | Creates a private pay-to-ID note for an account, waits for the note to commit, and returns the note with proof of its inclusion. |

`RequestFunds` returns the note in full. The node does not store the details of a private note, so a client that loses
the response cannot recover the funds.

The service does not authenticate requests. Restrict access to the API with a proxy or a load balancer.

Requests that arrive while a transaction is in progress share the next transaction, up to `--max-notes-per-tx`. A client
that tops up several accounts at once therefore waits for one transaction rather than one per account.

## Health and errors

The gRPC health service reports `funding_service.Api` as `SERVING` once the process has started. It is a liveness signal
and does not track whether the node is reachable. A request which cannot be served fails on its own, with `UNAVAILABLE`
when the node is unreachable or the service is stopping.

Each error carries a one byte code in the gRPC status details.

| Code | Status                | Meaning                                                                                                   |
| ---- | --------------------- | --------------------------------------------------------------------------------------------------------- |
| 0    | `INTERNAL`            | The service failed for a reason the client cannot act on.                                                 |
| 1    | `INVALID_ARGUMENT`    | The requested amount is zero.                                                                             |
| 2    | `INVALID_ARGUMENT`    | The requested amount exceeds `--max-amount`.                                                              |
| 3    | `FAILED_PRECONDITION` | The funding account cannot cover the request plus the fee of one transaction. An operator must add funds. |
| 4    | `UNAVAILABLE`         | The node is unreachable, or the service is shutting down.                                                 |
| 5    | `ABORTED`             | The funding transaction did not commit before it expired. No note was created.                            |
| 6    | `ABORTED`             | The node rejected the funding transaction. No note was created.                                           |
| 7    | `RESOURCE_EXHAUSTED`  | Too many requests are queued.                                                                             |

A malformed account ID is rejected with `INVALID_ARGUMENT` and no code. Every error other than 0 to 3 is safe to retry.

## Keep the account funded

`Status` reports the funding account's balance, which is the value to alert on. The service does not refill itself. Send
a pay-to-ID note that holds the native asset to the funding account to top it up, and consume it with a client that
holds the account's key.
