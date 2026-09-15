# Miden large account benchmark

A self-contained tool for the ntx-builder large-account benchmark. It seeds an oversized network account into a genesis
configuration, then submits an increment against it on a running chain and asserts the ntx-builder consumes it.

## The short version

`scripts/large-account-harness.sh` does everything below in one command: seeds the pair, brings up a local network with
it committed at genesis via `scripts/run-node.sh`, submits one increment, and asserts the counter advances.

```bash
MAP_ENTRIES=1000 ./scripts/large-account-harness.sh
```

```text
Seeding the wallet + counter pair (10000 map entries)

Measuring the account in isolation (no network)

Starting the local network

Submitting an increment and waiting for the counter to advance

PASS — the ntx-builder loaded the account and consumed the network note

10000 map entries
  counter on disk          628.8 KiB (64 B/entry)
  wallet on disk           4.2 KiB
  account in isolation     83.4 MiB resident, 128.2 MiB peak, 91.7 ms to load
  ntx-builder peak RSS     339.4 MiB
  sequencer peak RSS       450.8 MiB
  timings                  6s ready, 1.50s proving, 2 blocks to consume
```

## Seeding

```bash
miden-large-account-benchmark seed --output-dir ./seeded --counter-map-entries 1000000
```

This writes `faucet.mac`, `wallet.mac` (both carrying their signing key) and `counter.mac` into `./seeded`, and prints
all three account ids. Reference them from a genesis configuration:

```toml
native_faucet = "seeded/faucet.mac"
validators = ["<miden-validator pubkey>"]

[fee_parameters]
verification_base_fee = 0

[[account]]
path = "seeded/wallet.mac"

[[account]]
path = "seeded/counter.mac"
```

Paths are resolved relative to the genesis configuration file's directory. Build the genesis block and bootstrap each
service from it:

```bash
miden-validator genesis --genesis-block-directory ./genesis --accounts-directory ./accounts \
  --config ./genesis.toml
miden-validator   bootstrap --data-directory ./data/validator   --genesis ./genesis/genesis.dat
miden-node        bootstrap --data-directory ./data/node        --genesis ./genesis/genesis.dat
miden-ntx-builder bootstrap --data-directory ./data/ntx-builder --genesis ./genesis/genesis.dat
```

## Verifying the setup

Once the network is up, check the whole path works before measuring anything. `verify` submits a single increment and
asserts the counter advances:

```bash
miden-large-account-benchmark verify --accounts-dir ./seeded \
  --rpc-url http://localhost:57291 \
  --validator-signing-public-key "$VALIDATOR_1_PUBKEY" \
  --validator-signing-public-key "$VALIDATOR_2_PUBKEY"
```

It exits zero only if the counter moved, which requires every part of the chain to be working: the seeded accounts are
on chain, the node accepts a transaction against the wallet, and the ntx-builder can load an account this large and
consume the network note. The verifier obtains the genesis protocol configuration from RPC and checks it against the
genesis header and the seeded counter's fee asset. Anything less exits non-zero with the reason.

```text
baseline: counter=0 chain_tip=42
submitted increment at block 43 · proved in 1.38s · tx 0x8f2c…
waiting up to 20 blocks for the ntx-builder to consume the note...
  counter=0 blocks_elapsed=1/20
  counter=0 blocks_elapsed=2/20
counter advanced to 1 after 3 blocks
PASS: the ntx-builder loaded the account and consumed the network note
```

The budget is counted in blocks (`--wait-blocks`, 20 by default) rather than seconds, so it does not depend on how fast
the network produces them.

## License

This project is [MIT licensed](../../LICENSE).
