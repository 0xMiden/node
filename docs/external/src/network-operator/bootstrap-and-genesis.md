---
title: "Bootstrap and Genesis"
sidebar_position: 3
---

<!-- markdownlint-disable MD033 MD041 -->

import Tabs from "@theme/Tabs"; import TabItem from "@theme/TabItem";

# Bootstrap and Genesis

The genesis block is the trust anchor for every service that joins a network. It is not signed: it simply commits to the
full validator set in its header, and that set must sign every block after genesis. Because nothing signs the genesis
block, it must always be obtained from a trusted source. One of the network's operators is responsible for building it
from the genesis configuration. On official networks, the validators are operated by separate entities from the network
operator.

The genesis block is subsequently made available for official networks at

```text
https://genesis.<network>.miden.io
```

which provides an easy method to obtain this data. This is directly supported by service bootstrap commands by passing
`--network testnet` or `--network devnet`. Bootstrap commands also support passing a file directly to cover custom
networks, or if the official URLs are not trusted.

## Bootstrap Flow

<Tabs groupId="network-operator-genesis-source" defaultValue="official">
  <TabItem value="official" label="Official network">

The genesis block is the chain's trust root: its header commits to the full validator set, which must sign every block
after genesis. Each validator operator first prints their public key and sends it to the bootstrapping operator:

```bash
miden-validator pubkey --signing-key.kms-id <validator-N-kms-key-id>
```

The full validator set is passed on the command line, as one `--validator.key` flag per validator. There is no default
set: the flag is required.

**One** operator then runs `genesis` with the genesis configuration and the collected keys. Building the genesis block
requires no signing key:

```bash
miden-validator genesis \
  --genesis-block-directory genesis-data \
  --accounts-directory accounts \
  --config genesis.toml \
  --validator.key <validator-1-public-key-hex> \
  --validator.key <validator-2-public-key-hex> \
  --validator.key <validator-3-public-key-hex>
```

Unless the configuration sets `native_faucet` to a pre-built account file, the native faucet is generated as a network
account and holds no key of its own; minting from it is restricted to the faucet operator account generated alongside
it. The operator starts with 1,000 MIDEN tokens so it can pay fees for the first mint requests. Both accounts are
written to the accounts directory as `native_faucet.mac` and `faucet_operator.mac`, and the faucet account id is
printed. The operator file carries the only signing key permitted to mint, so treat it as a secret.

To run a faucet against the network, pass `faucet_operator.mac` to the faucet's `init --import`, and the faucet account
id to `--faucet-account-id`.

Upload `genesis-data/genesis.dat` so it is served at:

```text
https://genesis.<network>.miden.io
```

Every validator operator — including the one that built the genesis block — seeds their own database from the genesis
block:

```bash
miden-validator bootstrap \
  --data-directory validator-1-data \
  --genesis genesis-data/genesis.dat
```

Initialize the sequencer's node storage from the hosted genesis block:

```bash
miden-node bootstrap \
  --data-directory node-data \
  --network testnet
```

Initialize the network transaction builder from the same hosted genesis block:

```bash
miden-ntx-builder bootstrap \
  --data-directory ntx-builder-data \
  --network testnet
```

For `devnet`, use `--network devnet` instead. The `--network` flag is shorthand for downloading the genesis block from
`https://genesis.<network>.miden.io`.

Each validator operator's own KMS key ID must be used when that operator starts their validator for this network.

  </TabItem>
  <TabItem value="unofficial" label="Unofficial network">

**One** operator builds the genesis block; no signing key is needed. The genesis header commits to the full validator
set, passed as one `--validator.key` flag per validator; there is no default set. Each validator operator generates a
key-pair with `miden-validator keygen` (or prints the public key of an existing secret with
`miden-validator pubkey --signing-key.hex <validator-N-key-hex>`) and sends the public key to the bootstrapping
operator.

```bash
miden-validator genesis \
  --genesis-block-directory genesis-data \
  --accounts-directory accounts \
  --config genesis.toml \
  --validator.key <validator-1-public-key-hex> \
  --validator.key <validator-2-public-key-hex> \
  --validator.key <validator-3-public-key-hex>
```

Distribute `genesis-data/genesis.dat` to the validator operators, who each seed their own database from it — including
the operator who built the genesis block:

```bash
miden-validator bootstrap \
  --data-directory validator-1-data \
  --genesis genesis-data/genesis.dat
```

For unofficial networks or pre-publication testing, distribute the genesis block file directly and initialize services
from that file:

```bash
miden-node bootstrap \
  --data-directory node-data \
  --genesis genesis-data/genesis.dat
```

```bash
miden-ntx-builder bootstrap \
  --data-directory ntx-builder-data \
  --genesis genesis-data/genesis.dat
```

  </TabItem>
</Tabs>

The key each validator operator starts their validator with must match the public key committed for them via the
`genesis` command's `--validator.key` flags.

## Storage Key Ceremony

After genesis is built, every listed validator must join one DKG ceremony before validator startup. The ceremony creates
the shared public storage key and one distinct secret share per validator. No coordinator can derive those shares.

For the normal flow, one operator starts the durable Iroh board and sends its private ticket to each validator through
an authenticated and confidential bootstrap channel. Each validator runs the full ceremony with the signing key
committed in genesis. The board carries only public ceremony artifacts. Validator signatures authenticate registrations
and transcript checkpoints. Each validator keeps its identity, private DKG state, and final secret share local. The
manual file commands remain available for recovery. The DKG and database bootstrap may run in either order, but both
must finish before the validator starts.

All listed validators must contribute to the ceremony even when the recovery threshold is lower. If any participant
drops out or any transcript differs, discard the incomplete ceremony and start a new one with fresh identities and
sessions. See [storage key setup](./validator.md#storage-key-setup) for the commands and file rules.

Bootstrap takes no transaction encryption key: that key is configured separately when the validator is started, and
nothing cross-checks it against the genesis block. Every validator must be started with the same encryption key; the
validator refuses to start without one. See [Validator](./validator.md) for how to provision it.

<!-- markdownlint-enable MD033 MD041 -->
