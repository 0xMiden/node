# Miden funding service

`miden-funding-service` is a Miden node binary that sends the chain's native asset to any account that asks for it.

## Operation

The service holds no chain state. It reads the funding account from the node before every transaction, so a restart
needs no recovery. Only the account file, which holds the account ID and its signing key, is on disk.

Each request creates a public pay-to-ID note for the requested account. The service waits until the note is committed in
a block, then returns the note together with proof of its inclusion.

The service reads the chain's protocol configuration from the node at startup, together with the genesis block header.

The service serves a JSON HTTP API.

`POST /request-funds` takes the target `account_id`, in hexadecimal, and an `amount` in base units. It answers with the
note, its inclusion proof and the transaction which created it, each serialized and hexadecimal. The note is returned in
full because the requester does not know the note ID before the answer arrives. A requester which loses the answer can
still find the note at the node, through the note tag of the target account.

`GET /status` reports the funding account, its balance, the block that balance was read at, and the verification base
fee of that block. An operator alerts on that balance, because the service does not refill itself.

The service does not authenticate requests. An operator must restrict access to its HTTP API at the infrastructure
level.

## License

This project is [MIT licensed](../../LICENSE).
