# Miden funding service

`miden-funding-service` is a Miden node binary that sends the chain's native asset to any account that asks for it.

## Operation

The service holds no chain state. It reads the funding account from the node, so a restart needs no recovery. Only the
account file, which holds the account ID and its signing key, is on disk.

The service reads the chain's protocol configuration from the node at startup, together with the genesis block header.

The service serves a JSON HTTP API. `GET /status` reports the funding account, its balance, and the block that balance
was read at. An operator alerts on that balance, because the service does not refill itself.

The service does not authenticate requests. An operator must restrict access to its HTTP API at the infrastructure
level.

## License

This project is [MIT licensed](../../LICENSE).
