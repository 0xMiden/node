# Miden funding service

`miden-funding-service` is a Miden node binary that sends the chain's native asset to any account that asks for it.

## Operation

The service sends funds from a public account that an operator keeps funded. Refill it by sending a public pay-to-ID
note containing the native asset. The service never mints.

HTTP 200 confirms that a request has been durably accepted. Its note is created on chain asynchronously, and pending
requests survive restarts.

See the [operator documentation](../../docs/external/src/network-operator/funding-service.md) for account provisioning,
setup, startup, upgrades, and recovery.

The service serves a JSON HTTP API.

`POST /request-funds` takes the target `account_id`, in hexadecimal, and an `amount` in base units. It answers with the
serialized note, in hexadecimal. A requester which loses the answer can still find the note at the node, through the
note tag of the target account.

`GET /status` reports the funding account, the asset ID, symbol, decimals and name of the native asset, the balance, the
block that balance was read at, and the verification base fee of that block.

The service does not authenticate requests. An operator must restrict access to its HTTP API at the infrastructure
level.

## License

This project is [MIT licensed](../../LICENSE).
