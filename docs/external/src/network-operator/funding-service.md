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
| `--poll-interval`                | `1s`         | Interval for processing pending notes and checking submitted transactions.                                                                                              |
| `--deposit-scan-interval`        | `1m`         | How often the service scans for the pay-to-ID notes sent to the funding account.                                                                                        |
| `--http.timeout`                 | `30s`        | Largest duration allocated to one HTTP request.                                                                                                                         |
| `--rpc.timeout`                  | `10s`        | Timeout of a request to the node.                                                                                                                                       |
| `--tx-prover.timeout`            | `1m`         | Timeout of a request to the remote prover.                                                                                                                              |

`--tx-expiration-delta` is an upper bound, not a fixed value. A funding transaction reads the chain's fee configuration,
and the protocol lowers the expiration delta of a transaction which reads mutable state. A funding transaction therefore
expires at or before the requested block.

A funding request is answered without a call to the node, so `--http.timeout` only has to cover the service's own work.

Every option also reads from an environment variable named `MIDEN_FUNDING_<OPTION>`, for example
`MIDEN_FUNDING_ACCOUNT_FILE`.

## API

The service serves a JSON over HTTP API on `--listen`.

| Endpoint              | Purpose                                                                                                                                                                     |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GET /status`         | Returns the service version, the funding account's ID, its balance, the block the service is synchronized to, the configured maximum amount, and the verification base fee. |
| `POST /request-funds` | Creates a public pay-to-ID note for an account, returns it at once, and queues it for the next funding transaction.                                                         |

A funding request names the target account and the amount in base units:

```json
{ "account_id": "0x...", "amount": 1000000 }
```

The account ID is hexadecimal with a `0x` prefix. The response carries the note as the hexadecimal encoding of the
serialized object, without a prefix:

```json
{ "note": "..." }
```

The service answers **before** it submits the transaction that creates the note, so the note is not on chain yet. The
service retries requests while it runs. Accepted requests are held in memory and can be lost on restart. A client that
needs the note on chain either polls the node for the note ID or consumes the note as an unauthenticated input note,
which the node authenticates when it builds the block. The notes are public, so the node stores their details once they
commit.

The service does not authenticate requests. Restrict access to the API with a proxy or a load balancer.

Requests that arrive while a transaction is in progress share the next transaction, up to `--max-notes-per-tx`. A client
that tops up several accounts at once is therefore served by one transaction rather than one per account.

## Health and errors

The service has no health endpoint. `GET /status` answers while the service still synchronizes, so it reports that the
process runs and does not track whether the node is reachable. A request that cannot be served fails on its own.

A failed request answers with a JSON body that holds the reason:

```json
{ "error": "the requested amount must not be zero" }
```

The status code tells a client whether to change the request, add funds, or send the request again.

| Status                      | Meaning                                                                                                                       |
| --------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `400 Bad Request`           | The account ID is malformed or names the funding account, the requested amount is zero, or the amount exceeds `--max-amount`. |
| `408 Request Timeout`       | The request ran longer than `--http.timeout`.                                                                                 |
| `412 Precondition Failed`   | The balance the service last read does not cover the request plus the fee of one transaction.                                 |
| `429 Too Many Requests`     | Too many notes are queued.                                                                                                    |
| `500 Internal Server Error` | The service failed for a reason the client cannot act on.                                                                     |
| `503 Service Unavailable`   | The service is shutting down.                                                                                                 |

A request that fails created no note, and a client may send it again as it is. The service builds the note before it
answers. A 200 response names the queued note, but does not guarantee delivery across a service restart.

The 412 check is best effort. It reads the balance of an earlier block and does not account for the notes already
queued, so a request it admits can still wait in the queue until a deposit raises the balance. Raising the balance is an
operator action, which is what the status code reports.

## Keep the account funded

`GET /status` reports the funding account's balance, which is the value to alert on.

To refill the account, send it a **public** pay-to-ID note that holds the native asset. The service scans for those
notes and consumes them on its own, so no operator action is needed beyond sending the note. The scan runs every
`--deposit-scan-interval`, which defaults to one minute. At startup, the worker first scans from genesis through the
current chain tip. It completes that discovery before it processes funding requests. A restart recovers unspent
deposits, including deposits sent while the service was stopped. Periodic scans continue from the saved cursor.

A note is only collected when all of the following hold. Anything else is ignored, because the note tag encodes only the
leading bits of an account ID, so notes for other accounts reach the service too, and anyone can send a note that holds
whatever they like.

| Requirement                                | Why                                                                                      |
| ------------------------------------------ | ---------------------------------------------------------------------------------------- |
| The note is public                         | The node does not store the details of a private note, so the service cannot consume it. |
| It is a pay-to-ID note                     | Any other script may not release its assets to the account.                              |
| It targets the funding account             | The tag alone does not prove the target.                                                 |
| It holds the native asset and nothing else | Another asset would sit in the vault without the service being able to spend it.         |

A deposit and queued payouts can share one transaction and one fee, even when the account balance is zero. The worker
handles node rejections immediately. A state-conflict rejection with error byte `2` discards only the selected deposit.
The payouts remain queued. Accepted transactions and uncertain transport failures are monitored until commitment or
expiration. Other rejections and expiration retain the notes for retry.

Run only one writer for the funding account. The service deduplicates deposits by nullifier within its deposit pool. It
checks the recovered pool against the full nullifier history at startup. Periodic discovery does not check nullifiers;
the node rejects transactions with spent inputs. Failed note lookups retry the same page. Failed startup nullifier
checks retry against the recovered pool without scanning the notes again.

One transaction consumes at most one deposit, selected by largest amount. A transaction that consumes a deposit and
creates no funding note is only submitted when that deposit is worth more than the fee, so a note holding a single base
unit cannot be used to make the account spend more than it gains.
