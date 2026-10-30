# miden-genesis

Builds a Miden network's genesis **offline**, before any network exists. The tool first builds the genesis xUSDC faucet
and its distributor and writes their `.mac` account files, then builds the genesis block that commits to them. The
faucet id hashes the account seed plus the code and storage commitments (no chain state), so the id the tool prints is
the id the network boots with, reproducible from the config. Recording the consumed deposit nonces and prefunding the
distributor are later steps that leave the faucet id unchanged.

The config names the five role holders the `XReserveStablecoinBuilder` seeds, **owner** (`ADMIN`), **attest_admin**,
**pauser**, **unpauser**, **blocklist_manager**, by bare account id (hex or bech32). At launch the distributor doubles
as the bootstrap `ADMIN`: put its id in `accounts.owner` and leave the operational roles empty; they are assigned once
the network runs.

The faucet uses the V2 token policy manager. The faucet issues the network's fee asset, so every fee payment transfers
its asset. With V2, a pause stops mints and burns, but transfers and fee payments continue under the send and receive
policies. Without this, a paused faucet blocks every transaction, including the one that unpauses it.

## Install

```sh
make install-genesis                               # or: cargo install --path bin/genesis --locked
```

`miden-genesis` is then on `PATH`; `cargo run -p miden-genesis --` from the repo works the same. Release builds are also
published as the `miden-genesis` crate and container image.

## Usage

The four account commands work in the current directory: each reads its account inputs under their well-known names
(each `--flag` below can point elsewhere) and writes new output files. No command overwrites an existing file, so a
re-run needs the old output moved away first. Run the commands in launch order:

```sh
miden-genesis new-distributor [--auth-scheme ecdsa-k256-keccak|falcon512-poseidon2]
miden-genesis faucet --owner <distributor-id> --token-supply <base-units> --verification-base-fee <fee> [...]
miden-genesis prefund [--faucet usdcx-faucet.mac] [--distributor distributor.mac]
miden-genesis record-nonces --nonce <hex> [--nonce <hex> ...] [--faucet usdcx-faucet.mac]
miden-genesis build --genesis-block-directory <dir> --accounts-directory <dir> \
  --native-faucet usdcx-faucet.genesis.mac --funding-account distributor.genesis.mac \
  --verification-base-fee <fee> --timestamp <unix-seconds> --validator.key <hex> [--validator.key <hex> ...]
```

1. `new-distributor` generates a fresh public basic wallet with a new signing key (ECDSA secp256k1/keccak by default,
   Falcon512Poseidon2 on request) and writes it, key included, as `distributor.mac`: undeployed (nonce zero, empty
   vault), exactly what a wallet created with `miden-client new-wallet --account-type public` and exported with its keys
   looks like; that file is accepted in step 3 too. Prints the distributor id: hex, bech32 for mainnet/testnet/devnet,
   and the bytes32 form that is the deposit's `remoteRecipient` on the xReserve side (the id right-aligned in 32 bytes;
   the layout is `DEV-10`, open with Circle). The id is the `--owner` of step 2. Every command prints its ids in the
   same four forms. The command also writes `distributor.secret`, which contains the signing key without the account
   state. Both files contain the same key and are readable only by their owner. The `.secret` file contains the binary
   serialization of `AuthSecretKey`, including its signature scheme. Keep these files private. If generation fails after
   creating one output, preserve the files and retry in an empty directory.
2. `faucet` builds the genesis faucet from its flags (see [Faucet flags](#faucet-flags)) and writes it as
   `usdcx-faucet.mac` (nonce one, no seed). Prints the faucet id plus the role ids. Register this id with Circle and
   make the deposits against it.
3. `prefund` gives the distributor the faucet's whole recorded `--token-supply`, promotes it to genesis form (nonce one,
   no seed) and writes it, key included, as `distributor.genesis.mac`. It takes no amount: the faucet records the supply
   as issued, and the distributor's balance must equal it (the faucet's burn path is bounded by that counter). The
   distributor must be public, undeployed and carry a signing key; the command runs once per distributor.
4. `record-nonces` records the Circle deposit nonces given with `--nonce` (the hex of each nonce's 32 bytes, repeated or
   comma-separated) as consumed in the faucet and writes `usdcx-faucet.genesis.mac`. These are the nonces whose deposits
   the genesis state already honours: the prefunded balance is backed by them, and recording them keeps the relayer from
   minting them a second time. Recording a nonce twice is a no-op, so the flags can list every nonce so far. Run it
   after the deposits, when their nonces are known.
5. `build` assembles the genesis block from the two genesis-ready account files, the network parameters and the
   validator set, and writes it as `genesis.dat`. See [Build the genesis block](#build-the-genesis-block).

Steps 3 and 4 both read the faucet written by step 2 and are independent of each other. For a local network that never
sees Circle deposits, step 4 can be skipped and `build` takes `usdcx-faucet.mac` directly.

## Faucet flags

| Flag                      | Required | Meaning                                                                                                      |
| ------------------------- | -------- | ------------------------------------------------------------------------------------------------------------ |
| `--owner`                 | yes      | The single `ADMIN` holder's account id, hex or bech32: the distributor printed by `new-distributor`.         |
| `--token-supply`          | yes      | The initial supply in base units (6 decimals, so `100000000` is 100 USDC), the amount deposited with Circle. |
| `--verification-base-fee` | yes      | Baked into the faucet's fee schedule. Must equal the `--verification-base-fee` passed to `build`.            |
| `--seed`                  | no       | The faucet's 32-byte account seed as hex. Defaults to the ASCII of `USDCX-FAUCET` zero-padded to 32 bytes.   |
| `--domain`                | no       | The Circle domain id. Defaults to 10007, the Miden domain.                                                   |
| `--min-burn-amount`       | no       | The smallest amount a burn may redeem, in base units.                                                        |
| `--attester`              | no       | A deposit attester to allowlist, as the hex of its 33-byte compressed SEC1 key (`02` or `03` then x).        |
| `--attest-admin`          | no       | An `ATTEST_ADMIN` holder's account id.                                                                       |
| `--pauser`                | no       | A `DOM_PAUSER` holder's account id.                                                                          |
| `--unpauser`              | no       | A `DOM_UNPAUSER` holder's account id.                                                                        |
| `--blocklist-manager`     | no       | A `BLK_MANAGER` holder's account id.                                                                         |

The list flags (`--attester` and the four operational roles) take repeated flags or comma-separated values, and every
listed holder is seeded as a member of its role. A role with no holder is populated later through the standard
role-action note, and an empty attester list is seeded later through `set_attester` notes. Every byte-string value takes
an optional `0x` prefix. The seed and the supply both feed the faucet id, so they must be final before `faucet` runs;
the supply cap is not configurable and is set to the maximum asset amount. The tool cannot check that the fee matches
the one later passed to `build`.

## Build the genesis block

The genesis block is the chain's trust root. It is not signed: its header commits to the full validator set, and that
set must sign every block after genesis. **One** operator builds it; each validator operator first prints their public
key with `miden-validator pubkey` (or generates a key-pair with `miden-validator keygen`) and sends it to that operator.

```sh
miden-genesis build \
  --genesis-block-directory genesis-data \
  --accounts-directory accounts \
  --native-faucet usdcx-faucet.genesis.mac \
  --funding-account distributor.genesis.mac \
  --verification-base-fee 7 \
  --timestamp <unix-seconds> \
  --validator.key <validator-1-public-key-hex> \
  --validator.key <validator-2-public-key-hex> \
  --validator.key <validator-3-public-key-hex>
```

| Flag                        | Environment variable                  | Meaning                                                                                                      |
| --------------------------- | ------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `--genesis-block-directory` |                                       | Directory that receives `genesis.dat`. Must not exist or be empty.                                           |
| `--accounts-directory`      |                                       | Directory that receives the generated account files. Must not exist or be empty.                             |
| `--native-faucet`           | `MIDEN_GENESIS_NATIVE_FAUCET`         | The faucet written by `record-nonces` (or `faucet`). Its asset is the network's fee asset.                   |
| `--funding-account`         | `MIDEN_GENESIS_FUNDING_ACCOUNT`       | The prefunded distributor written by `prefund`. Must be public.                                              |
| `--verification-base-fee`   | `MIDEN_GENESIS_VERIFICATION_BASE_FEE` | Base fee in base units of the native asset. Must equal the faucet config's `verification_base_fee`.          |
| `--timestamp`               | `MIDEN_GENESIS_TIMESTAMP`             | Genesis timestamp in seconds since the Unix epoch.                                                           |
| `--validator.key`           | `MIDEN_GENESIS_VALIDATOR_KEYS`        | Hex-encoded validator public key; repeat per validator. The variable takes a comma-separated list. Required. |
| `--accounts-config`         | `MIDEN_GENESIS_ACCOUNTS_CONFIG`       | Optional TOML file with additional accounts.                                                                 |

Both account files are taken as they are and must already have nonzero nonces, which is why `prefund` and
`record-nonces` emit the genesis form. Genesis does not need their signing keys; `distributor.genesis.mac` carries the
distributor's key regardless, so keep the genesis working directory private.

The additional accounts TOML takes `[[wallet]]`, `[[fungible_faucet]]` and `[[account]]` entries. Each `[[wallet]]`
needs a unique `name` and lists its `assets` by faucet `symbol`; `build` generates its key and writes `<name>.mac` to
the accounts directory. Each `[[fungible_faucet]]` defines a faucet by `symbol`, `decimals` and `max_supply` and is
written as `faucet_<symbol>.mac`. Each `[[account]]` imports an existing account file by `name` and `path` (relative to
the TOML file) without validation. Do not list `[[wallet]]` entries holding the xUSDC symbol: the tool would overwrite
the faucet's recorded `token_supply` with their total.

On success, `build` prints the id of every genesis account and the `bootstrap` commands that seed the validators, the
node and the network transaction builder from `genesis.dat`. See the
[bootstrap and genesis guide](../../docs/external/src/network-operator/bootstrap-and-genesis.md) for distributing the
file.

The `.mac` format follows the protocol version this workspace pins; every service bootstrapping from the genesis block
must be on the same protocol family.
