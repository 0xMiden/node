---
title: "Funding Service"
sidebar_position: 8
---

# Funding Service

The funding service sends the chain's native asset to any account that asks for it. It owns one wallet account, which
holds the native asset, and creates a public pay-to-ID note for each request.

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

The name is required, and `miden-validator genesis` writes the account file to
`<accounts-directory>/funding_service.mac`, so the service loads it from a fixed path. The account must be public: the
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
| `--listen`                       | required     | Socket address of the HTTP API.                                                                                                                                         |
| `--rpc.url`                      | required     | The node RPC API the service reads from and submits to.                                                                                                                 |
| `--account-file`                 | required     | Path to the funding account's `.mac` file.                                                                                                                              |
| `--validator-signing-public-key` | required     | Hex-encoded validator signing public key trusted to attest the transaction encryption key. Repeat the flag, or pass a comma separated list, to trust more than one key. |
| `--tx-prover.url`                | none         | Remote transaction prover. Without it the service proves in process.                                                                                                    |
| `--max-amount`                   | `1000000000` | Largest amount one request may ask for, in base units.                                                                                                                  |
| `--max-notes-per-tx`             | `16`         | Largest number of notes one transaction creates. Must not exceed 100.                                                                                                   |
| `--tx-expiration-delta`          | `50`         | Largest number of blocks after its reference block at which a funding transaction expires.                                                                              |
| `--poll-interval`                | `1s`         | How often the service asks the node whether its notes are committed.                                                                                                    |
| `--http.timeout`                 | `5m`         | Largest duration allocated to one HTTP request.                                                                                                                         |
| `--rpc.timeout`                  | `10s`        | Timeout of a request to the node.                                                                                                                                       |
| `--tx-prover.timeout`            | `1m`         | Timeout of a request to the remote prover.                                                                                                                              |

`--tx-expiration-delta` is an upper bound, not a fixed value. A funding transaction reads the chain's fee configuration,
and the protocol lowers the expiration delta of a transaction which reads mutable state. A funding transaction therefore
expires at or before the requested block.

A funding request blocks until the note is committed, so `--http.timeout` must exceed the proving time plus the
expiration window (`--tx-expiration-delta` multiplied by the chain's block interval). Raise it where proving is slow. A
client must set a matching deadline of its own.

Every option also reads from an environment variable named `MIDEN_FUNDING_<OPTION>`, for example
`MIDEN_FUNDING_ACCOUNT_FILE`.

## API

The service serves a JSON over HTTP API on `--listen`.

| Endpoint              | Purpose                                                                                                                                                                     |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GET /status`         | Returns the service version, the funding account's ID, its balance, the block the service is synchronized to, the configured maximum amount, and the verification base fee. |
| `POST /request-funds` | Creates a public pay-to-ID note for an account, waits for the note to commit, and returns the note with proof of its inclusion.                                             |

A funding request names the target account and the amount in base units:

```json
{ "account_id": "0x...", "amount": 1000000 }
```

The account ID is hexadecimal with a `0x` prefix. The response carries the note, the proof that the note is in a block,
and the transaction that created it. Each value is the hexadecimal encoding of the serialized object, without a prefix:

```json
{ "note": "...", "inclusion_proof": "...", "transaction_id": "..." }
```

The notes are public, so the node stores their details.

The service does not authenticate requests. Restrict access to the API with a proxy or a load balancer.

Requests that arrive while a transaction is in progress share the next transaction, up to `--max-notes-per-tx`. A client
that tops up several accounts at once therefore waits for one transaction rather than one per account.

## Health and errors

The service has no health endpoint. `GET /status` answers while the service still synchronizes, so it reports that the
process runs and does not track whether the node is reachable. A request that cannot be served fails on its own.

A failed request answers with a JSON body that holds the reason:

```json
{ "error": "the requested amount must not be zero" }
```

The status code tells a client whether to change the request, add funds, or send the request again.

| Status                      | Meaning                                                                                                   |
| --------------------------- | --------------------------------------------------------------------------------------------------------- |
| `400 Bad Request`           | The account ID is malformed, the requested amount is zero, or the amount exceeds `--max-amount`.          |
| `408 Request Timeout`       | The request ran longer than `--http.timeout`.                                                             |
| `409 Conflict`              | The funding transaction did not commit before it expired, or the node rejected it. No note was created.   |
| `412 Precondition Failed`   | The funding account cannot cover the request plus the fee of one transaction. An operator must add funds. |
| `429 Too Many Requests`     | Too many requests are queued.                                                                             |
| `500 Internal Server Error` | The service failed for a reason the client cannot act on.                                                 |
| `503 Service Unavailable`   | The node is unreachable, or the service is shutting down.                                                 |

A request that fails with 409, 429, or 503 created no note, and a client may send it again as it is. After 408 or 500
the service may still have created the note, so a client that sends the request again may fund the account twice.

## Keep the account funded

`GET /status` reports the funding account's balance, which is the value to alert on. The service does not refill itself.
Send a pay-to-ID note that holds the native asset to the funding account to top it up, and consume it with a client that
holds the account's key.
