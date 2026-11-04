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

Prepare a public account using standard `AuthSingleSig` authentication, with a nonzero nonce and a balance of the native
asset. Pass its account file to `miden-validator genesis --funding-account`. Keep its account ID for bootstrap and its
signing key for startup. The service reads the current public account state from the node.

The signing-key file contains the binary serialization of `AuthSecretKey`, including its signature scheme. It supports
ECDSA secp256k1/Keccak and Falcon512Poseidon2. `miden-usdcx-genesis new-distributor` writes this file as
`distributor.secret` alongside the account file; see the
[genesis tool documentation](https://github.com/0xMiden/node/tree/main/crates/usdcx-genesis). For an existing account,
export its key in the same format. Restrict the key file to its owner and keep it outside the database directory; the
database contains no signing key.

## Initialize the database

Bootstrap binds the service's database to a network and public funding account ID. It does not need the signing key.
Keep the data directory on persistent storage and run only one service instance for that funding account.

For an official network, bootstrap downloads and validates genesis from `https://genesis.<network>.miden.io`:

```bash
miden-funding-service bootstrap \
  --data-directory /opt/miden-funding-service/data \
  --account-id <funding-account-id> \
  --network testnet
```

Use `--network mainnet` or `--network devnet` for the other official networks. For a custom network or a separately
obtained trusted genesis file, replace `--network testnet` with `--genesis /path/to/genesis.dat`. See
[Bootstrap and Genesis](./bootstrap-and-genesis.md) for obtaining trusted genesis data.

The data directory must be absent or empty, and its parent directory must exist. Bootstrap needs no RPC connection. On
success, `funding.sqlite3` contains the network and funding account identity and is ready for `start`. Bootstrap refuses
to overwrite existing data. If initialization fails and leaves files behind, preserve those files for inspection and
retry in an empty directory after correcting the cause.

## Start

```bash
miden-funding-service start \
  --data-directory /opt/miden-funding-service/data \
  --listen 0.0.0.0:50401 \
  --rpc.url http://rpc-node:57291 \
  --tx-prover.url http://tx-prover:50051 \
  --signing-key-file /opt/miden-funding-service/funding.secret \
  --validator-signing-public-key <validator-signing-public-key>
```

| Option                           | Default      | Purpose                                                                                                                                                                 |
| -------------------------------- | ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--data-directory`               | required     | Directory containing the bootstrapped funding database.                                                                                                                 |
| `--listen`                       | required     | Socket address of the HTTP API.                                                                                                                                         |
| `--rpc.url`                      | required     | The node RPC API the service reads from and submits to.                                                                                                                 |
| `--signing-key-file`             | required     | Path to the funding account's serialized signing key.                                                                                                                   |
| `--validator-signing-public-key` | required     | Hex-encoded validator signing public key trusted to attest the transaction encryption key. Repeat the flag, or pass a comma separated list, to trust more than one key. |
| `--tx-prover.url`                | none         | Remote transaction prover. Without it the service proves in process.                                                                                                    |
| `--max-amount`                   | `1000000000` | Largest amount one request may ask for, in base units.                                                                                                                  |
| `--max-notes-per-tx`             | `16`         | Largest number of notes one transaction creates. Must not exceed 100.                                                                                                   |
| `--tx-expiration-delta`          | `50`         | Largest number of blocks after its reference block at which a funding transaction expires.                                                                              |
| `--poll-interval`                | `1s`         | Interval for syncing the wallet, discovering deposits, and checking submitted transactions.                                                                             |
| `--http.timeout`                 | `30s`        | Largest duration allocated to one HTTP request.                                                                                                                         |
| `--rpc.timeout`                  | `10s`        | Timeout of a request to the node.                                                                                                                                       |
| `--tx-prover.timeout`            | `1m`         | Timeout of a request to the remote prover.                                                                                                                              |

With `--tx-prover.url` set, the service proves only through the remote prover and never in process, so its host does not
need the memory that proving requires. If the remote prover fails or times out, the affected requests stay queued and
the service retries them on the next poll. An overloaded or unavailable prover therefore delays funding without taking
the service down. Watch for repeated proving failures in the service's logs and traces, and restore the prover to resume
funding.

`--tx-expiration-delta` is an upper bound, not a fixed value. A funding transaction reads the chain's fee configuration,
and the protocol lowers the expiration delta of a transaction which reads mutable state. A funding transaction therefore
expires at or before the requested block.

A funding request is answered without a call to the node. `--http.timeout` covers the service's own work, including
committing the note to SQLite.

Runtime options also read from an environment variable named `MIDEN_FUNDING_<OPTION>`, for example
`MIDEN_FUNDING_SIGNING_KEY_FILE`.

Startup requires an existing database with the current schema. The service reads the account ID from SQLite, checks the
stored network identity against the connected node, and loads the public account state and current fee before opening
the HTTP listener. Startup checks that the signing key and signature scheme match the account. The signing key is read
once at startup and kept in memory for signing transactions. If the database is missing, run `bootstrap`. If migrations
are pending, stop the service and follow the procedure below. A network mismatch requires the correct RPC endpoint and
data directory; migrating does not change the database's identity.

## Migrate the database

Apply migrations when a service upgrade requires a newer database schema. Stop the service and back up its complete data
directory first, then run:

```bash
miden-funding-service migrate --data-directory /opt/miden-funding-service/data
```

Migration uses only the existing database; it needs no genesis download, signing key, or RPC connection. A successful
exit means the database has the current schema and the service can be started again. Each migration is verified and
committed in a single transaction. If migration fails, keep the service stopped, correct the reported cause, and rerun
`migrate` against the same database.

## API

The service serves a JSON over HTTP API on `--listen`.

| Endpoint              | Purpose                                                                                                                                                                     |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GET /status`         | Returns the service version, the funding account's ID, its balance, the block the service is synchronized to, the configured maximum amount, and the verification base fee. |
| `POST /request-funds` | Creates and persists a public pay-to-ID note for an account, returns it, and queues it for the next funding transaction.                                                    |

A funding request names the target account and the amount in base units:

```json
{ "account_id": "0x...", "amount": 1000000 }
```

The account ID is hexadecimal with a `0x` prefix. The response carries the note as the hexadecimal encoding of the
serialized object, without a prefix:

```json
{ "note": "..." }
```

HTTP 200 confirms that the returned note has been committed to SQLite. The service answers **before** it submits the
transaction that creates the note, so the note is not on chain yet. The service retries requests while it runs. Stored
requests survive a restart. Confirmed requests are retained for auditing and excluded from later batches.

After a restart, the service checks any unfinished transaction before creating another funding transaction. If it
committed, the service records delivery. Otherwise, it waits until the transaction expires and the node confirms that it
did not commit before retrying its requests. An unreachable node delays recovery; it does not cause the service to retry
a transaction whose outcome is unknown. The service does not retain the transaction payload, so it cannot rebroadcast
it. A crash before submission can therefore leave requests waiting until that transaction's expiration.

A client that needs the note on chain either polls the node for the note ID or consumes the note as an unauthenticated
input note, which the node authenticates when it builds the block. The notes are public, so the node stores their
details once they commit.

The service does not authenticate requests. Restrict access to the API with a proxy or a load balancer.

The worker checks for pending requests at startup and waits `--poll-interval` between funding attempts. Requests that
arrive between checks are grouped into batches in acceptance order, up to `--max-notes-per-tx`. Requests can accumulate
while a transaction is in progress. The backlog has no configured capacity limit; requests wait for their database write
and are subject to `--http.timeout`.

## Health and errors

The service has no health endpoint. `GET /status` answers while the service still synchronizes, so it reports that the
process runs and does not track whether the node is reachable. A request that cannot be served fails on its own.

The reported balance, block, and fee are loaded before HTTP starts and updated whenever the worker completes a wallet
sync. They remain unchanged while the worker proves a transaction, waits for confirmation, or retries a failed sync.

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
| `500 Internal Server Error` | The service failed for a reason the client cannot act on.                                                                     |

Validation errors reject requests before persistence. A database write can finish after an HTTP timeout, so a timeout
does not establish whether the note was persisted. Retrying a request creates a new note.

The 412 check is best effort. It reads the balance of an earlier block and does not account for the notes already
queued, so a request it admits can still wait in the queue until a deposit raises the balance. Raising the balance is an
operator action, which is what the status code reports.

## Keep the account funded

`GET /status` reports the funding account's balance, which is the value to alert on.

To refill the account, send it a **public** pay-to-ID note that holds the native asset. The service scans for those
notes and consumes them on its own, so no operator action is needed beyond sending the note. The worker syncs at
`--poll-interval`, which defaults to one second, while no transaction is in flight. At startup, the worker first scans
from genesis through the current chain tip. It completes that discovery before it processes funding requests. A restart
recovers unspent deposits, including deposits sent while the service was stopped. Periodic scans continue from the saved
cursor.

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

If the node cannot serve a deposit or check whether it has been spent, funding waits for synchronization to succeed. The
service retries these failures automatically and checks the recovered deposits against the chain after a restart.

One transaction consumes at most one deposit, selected by largest amount. A transaction that consumes a deposit and
creates no funding note is only submitted when that deposit is worth more than the fee, so a note holding a single base
unit cannot be used to make the account spend more than it gains.
