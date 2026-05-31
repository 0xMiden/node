# Miden network monitor

`miden-network-monitor` is a dashboard and health-check binary for Miden network infrastructure. It
is part of the Miden node repository; see the
[repository README](https://github.com/0xMiden/node#readme) for the overall project layout.

## Role

The monitor checks the health and freshness of services around a Miden network. Depending on its
configuration, it can monitor:

- the public node RPC API;
- remote prover services;
- a faucet service;
- an explorer endpoint;
- a note transport service;
- the validator service;
- an end-to-end network transaction flow using temporary in-memory accounts.

The monitor serves a web dashboard and can emit OpenTelemetry traces when standard OTLP environment
variables are configured.

## Operation

The monitor is an observer and test client, not a node component required for block production. Its
network transaction checks create fresh in-memory accounts on startup and do not persist account
state to disk.

Use the binary help output for the current command and configuration surface. The help output is the
source of truth for flags and environment variables.

## License

This project is [MIT licensed](../../LICENSE).
