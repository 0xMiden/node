# Miden network monitor

`miden-network-monitor` is a dashboard and health-check binary for Miden network infrastructure. It is part of the Miden
node repository; see the [repository README](https://github.com/0xMiden/node#readme) for the overall project layout.

## Role

The monitor checks the health and freshness of services around a Miden network. Depending on its configuration, it can
monitor:

- the public node RPC API;
- remote prover services;
- a faucet service;
- a funding service;
- an explorer endpoint;
- a note transport service;
- named validator services;
- the Agglayer bridge, through the status endpoint of an agglayer-monitor instance;
- an end-to-end network transaction flow using temporary in-memory accounts.

The monitor serves a web dashboard and can emit OpenTelemetry traces when standard OTLP environment variables are
configured.

## Operation

The monitor is an observer and test client, not a node component required for block production. Its network transaction
checks create fresh in-memory accounts on startup and do not persist account state to disk.

On a network with account allowlist enforcement enabled, give the monitor a finite pool of invitation codes. Obtain
unused codes from the network operator and save their original text as a JSON array, for example:

```json
["first-invitation-code", "second-invitation-code"]
```

Set `MIDEN_MONITOR_REGISTRATION_CODES_FILE` to the file's path, or pass `--registration-codes-file /path/to/codes.json`.
For containers, mount the file and use its path inside the container. Codes are case-sensitive and are not trimmed;
empty strings and duplicates are rejected. Keep the file private and give each monitor instance its own pool.

The monitor registers its wallet before requesting funding or submitting transactions. Its network counter account does
not require registration. Each fresh pair consumes one code, so 100 unused codes support at most 100 pairs. Startup and
recovery use the same pool. Registration retries retain the same accounts and code when a response is uncertain; a
failure after registration, during funding or deployment, can consume codes without producing a usable pair.
Registration's automatic funding does not replace the monitor's configured funding service.

After a restart, the monitor tries codes in file order and skips any that registration reports as unknown or already
consumed; it does not persist accounts or update the file. When no usable codes remain, transaction checks report an
unhealthy status and the other checks continue. Obtain additional unused codes, update the file, and restart the monitor
to reload it. A missing or invalid file also leaves transaction checks unhealthy until corrected and the monitor
restarted. No file is required on networks with allowlist enforcement disabled. Remote prover probes do not submit their
temporary accounts and do not consume registration codes.

Network transaction checks require `MIDEN_MONITOR_VALIDATOR_SIGNING_PUBLIC_KEY`. The signing key must contain the
hex-encoded validator key that signs transaction encryption key attestations. The monitor will not submit a transaction
unless it can verify the advertised encryption key. The monitor obtains the active fee asset from the protocol
configuration returned by RPC and verifies it against the transaction's reference block.

On a chain with a non-zero verification base fee, network transaction checks additionally require
`MIDEN_MONITOR_FUNDING_SERVICE_URL`: the monitor funds its in-memory accounts from the funding service and tops the
balance up automatically when it runs low. Without it the monitor refuses to start its network transaction checks on
such chains. `MIDEN_MONITOR_FAUCET_URL` is only used for the faucet checks.

Each wallet funding request asks for `MIDEN_MONITOR_WALLET_FUNDING_AMOUNT` base units of the native asset, which
defaults to `1_000_000`. The wallet requests another top-up when its balance falls below a quarter of this amount.
Because the accounts live only in memory, every restart abandons the wallet's remaining balance, which can reach about
1.25 times the funding amount. The same happens when the monitor replaces its accounts after persistent transaction
failures. Choose an amount you can afford to lose on each restart: a smaller amount only means more frequent funding
requests. Keep the amount at or below the funding service's `--max-amount`, otherwise the service rejects every request
and the network transaction checks report the error.

Setting `MIDEN_MONITOR_FUNDING_SERVICE_URL` also enables a funding service card, even when network transaction checks
are disabled. The monitor reads `GET /status` at the status-check interval and displays the funding account, native
asset metadata, balance, chain tip, maximum request amount, and verification base fee. Amounts are shown in tokens,
using the native asset's decimal precision and symbol. A healthy card means the status endpoint returned a valid
response; it does not guarantee that a funding request can complete or that the account has enough funds. Failed
requests and invalid responses make the card unhealthy.

Configure each validator with a display name and URL. For example, to monitor two validators without running network
transaction checks:

```sh
miden-network-monitor start --disable-ntx-service \
  --validators 'Miden=https://miden-validator.example,Gateway=https://gateway-validator.example'
```

You can also repeat `--validators NAME=URL`, or set `MIDEN_MONITOR_VALIDATORS` to a comma-separated list of these pairs.
The Validators card summarizes how many validators are healthy and shows each validator's name, health, chain tip,
validated transactions, and signed blocks in a separate row. Checks run independently. Expand a failing validator's
error to see details; rows stack on narrow screens. Validator URLs are not displayed on the card. The existing
`--validator-url` and `MIDEN_MONITOR_VALIDATOR_URL` settings still configure a single validator named `Validator`; use
either the legacy setting or named validators, not both.

Each faucet check requests `MIDEN_MONITOR_FAUCET_MINT_AMOUNT` base units, which defaults to `1_000`. Keep this amount at
or below the faucet's maximum claimable amount, otherwise the faucet rejects every request and the faucet card stays
unhealthy. The faucet card shows its balance and base amount in tokens using the reported decimal precision. The faucet
metadata does not include a token symbol, so these values are labeled `tokens`.

The note transport check uses the standard gRPC health service for `miden.note_transport.v1.NoteTransportService`. Only
a `SERVING` response marks the service as healthy. Its dashboard card shows the service URL.

The Agglayer bridge check reads `GET /v1/status` from the agglayer-monitor API at `MIDEN_MONITOR_AGGLAYER_MONITOR_URL`.
The agglayer-monitor runs the E2E bridge tests between L1 and Miden. The monitor does not send bridge transactions. The
card status is the overall status that the agglayer-monitor reports. That status is unknown until both directions have a
result. The card is unhealthy when the endpoint is unreachable, returns an error, or uses an unsupported schema version.

Use the binary help output for the current command and configuration surface. The help output is the source of truth for
flags and environment variables.

## License

This project is [MIT licensed](../../LICENSE).
