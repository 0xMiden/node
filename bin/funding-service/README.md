# Miden funding service

`miden-funding-service` is a Miden node binary that sends the chain's native asset to any account that asks for it.

## Operation

Bootstrap initializes a SQLite database from trusted genesis data and the public funding account ID. Startup checks that
the database matches the connected network. Database creation and migration are explicit operations; see the
[operator documentation](../../docs/external/src/network-operator/funding-service.md) for the commands.

The database supplies the funding account ID, and the service reads its public state from the node before every
transaction. Startup reads the signing key from a separate key file. Each accepted note is committed to SQLite before
the service returns HTTP 200. Stored requests survive a restart, but the worker does not resume them or recover pending
transactions after a restart.

Each request creates a public pay-to-ID note for the requested account. The service persists the note before answering,
then creates it on chain in a later transaction. A single worker owns the account, keeps one transaction in flight, and
tracks each submitted transaction until its commitment or expiration is known. New requests stay in a bounded channel
while the worker processes one batch.

The account is refilled by sending it a public pay-to-ID note that holds the native asset. The service scans for those
notes and can consume one deposit in the same transaction that creates queued funding notes. The deposit can fund the
payouts and the transaction fee. A node rejection with state-conflict error byte `2` discards only the selected deposit.
The payouts remain queued for retry. Accepted transactions and uncertain transport failures are monitored until
commitment or expiration. Other node rejections and expiration retain the notes for retry.

At startup, the worker discovers deposits from genesis through the recorded chain tip before it processes requests. It
checks the recovered pool against the nullifier history to exclude spent notes. Periodic scans then continue from that
tip without nullifier checks. The node rejects transactions that try to consume spent deposits. A restart recovers
unspent deposits, including those sent while the service was stopped. Run only one writer for the funding account.

The service reads the chain's protocol configuration from the node at startup, together with the genesis block header.

The service serves a JSON HTTP API.

`POST /request-funds` takes the target `account_id`, in hexadecimal, and an `amount` in base units. It answers with the
serialized note, in hexadecimal. A requester which loses the answer can still find the note at the node, through the
note tag of the target account.

`GET /status` reports the funding account, the asset ID, symbol, decimals and name of the native asset, the balance, the
block that balance was read at, and the verification base fee of that block. An operator alerts on that balance, because
the service never mints.

The service does not authenticate requests. An operator must restrict access to its HTTP API at the infrastructure
level.

## License

This project is [MIT licensed](../../LICENSE).
