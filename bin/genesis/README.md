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

The four account commands work in the current directory: each reads its inputs under their well-known names (each
`--flag` below can point elsewhere) and writes new output files. No command overwrites an existing file, so a re-run
needs the old output moved away first. Start from copies of the crate's two templates, then run the commands in launch
order:

```sh
cp <repo>/bin/genesis/config.template.json config.json    # then replace every <...> value
cp <repo>/bin/genesis/nonces.template.json nonces.json    # then list the deposit nonces
miden-genesis new-distributor [--auth-scheme ecdsa-k256-keccak|falcon512-poseidon2]
miden-genesis faucet [--config config.json]
miden-genesis prefund [--faucet usdcx-faucet.mac] [--distributor distributor.mac]
miden-genesis record-nonces [--faucet usdcx-faucet.mac] [--nonces nonces.json]
miden-genesis build --genesis-block-directory <dir> --accounts-directory <dir> \
  --native-faucet usdcx-faucet.genesis.mac --funding-account distributor.genesis.mac \
  --verification-base-fee <fee> --timestamp <unix-seconds> --validator.key <hex> [--validator.key <hex> ...]
```

1. `new-distributor` generates a fresh public basic wallet with a new signing key (ECDSA secp256k1/keccak by default,
   Falcon512Poseidon2 on request) and writes it, key included, as `distributor.mac`: undeployed (nonce zero, empty
   vault), exactly what a wallet created with `miden-client new-wallet --account-type public` and exported with its keys
   looks like; that file is accepted in step 3 too. Prints the distributor id: hex, bech32 for mainnet/testnet/devnet,
   and the bytes32 form that is the deposit's `remoteRecipient` on the xReserve side (the id right-aligned in 32 bytes;
   the layout is `DEV-10`, open with Circle). The id goes into `config.json` as `accounts.owner`. Every command prints
   its ids in the same four forms. The command also writes `distributor.secret`, which contains the signing key without
   the account state. Both files contain the same key and are readable only by their owner. The `.secret` file contains
   the binary serialization of `AuthSecretKey`, including its signature scheme. Keep these files private. If generation
   fails after creating one output, preserve the files and retry in an empty directory.
2. `faucet` builds the genesis faucet from `config.json` and writes `usdcx-faucet.mac` (nonce one, no seed). Prints the
   faucet id plus the configured role ids. Register this id with Circle and make the deposits against it.
3. `prefund` gives the distributor the faucet's whole recorded `token_supply`, promotes it to genesis form (nonce one,
   no seed) and writes it, key included, as `distributor.genesis.mac`. It takes no amount: the faucet records the supply
   as issued, and the distributor's balance must equal it (the faucet's burn path is bounded by that counter). The
   distributor must be public, undeployed and carry a signing key; the command runs once per distributor.
4. `record-nonces` records the Circle deposit nonces listed in `nonces.json` as consumed in the faucet and writes
   `usdcx-faucet.genesis.mac`. Recording a nonce twice is a no-op, so the file can list every nonce so far. Run it after
   the deposits, when their nonces are known.
5. `build` assembles the genesis block from the two genesis-ready account files, the network parameters and the
   validator set, and writes it as `genesis.dat`. See [Build the genesis block](#build-the-genesis-block).

Steps 3 and 4 both read the faucet written by step 2 and are independent of each other. For a local network that never
sees Circle deposits, step 4 can be skipped and `build` takes `usdcx-faucet.mac` directly.

## Config

`config.template.json` in this crate is the placeholder form: copy it to `config.json` and replace every `<...>` value
(the template does not parse until they are): the distributor id and the attester key. It pre-fills the faucet seed (the
ASCII of `USDCX-FAUCET` zero-padded to 32 bytes: the seed is public and only has to be fixed before `faucet` runs), the
launch supply of 100 USDC, the Miden domain, the min burn amount, the launch `verification_base_fee` of 7, and the empty
operational roles. JSON, unknown fields rejected:

```json
{
  "accounts": {
    "owner": "0x6aeeb7cba03918516870e95568b77b",
    "attest_admins": ["0x... or bech32"],
    "pausers": ["0x... or bech32", "0x... several holders allowed"],
    "unpausers": ["0x... or bech32"],
    "blocklist_managers": ["0x... or bech32"]
  },
  "faucet": {
    "seed": "0x55534443582d4641554345540000000000000000000000000000000000000000",
    "token_supply": 100000000,
    "domain": 10007,
    "min_burn_amount": 1,
    "verification_base_fee": 7,
    "attesters": ["0x0279... (33 bytes of hex)"]
  }
}
```

`accounts.owner` is the single `ADMIN` holder's account id; the four operational role fields each list zero or more
holders (absent means empty; the role is then populated later through the standard role-action note). Every id is
`0x`-prefixed hex or bech32, and every listed holder is seeded as a member of its role. `faucet.seed` is the faucet's
32-byte account seed as a hex string (the `0x` prefix is optional on every byte-string field); `token_supply` is the
initial supply in base units (6 decimals, so `100000000` is 100 USDC), the amount deposited with Circle for the
distributor; it feeds the faucet id, so it must be final before `faucet` runs. The supply cap is not configurable and is
set to the maximum asset amount; `domain` is the Circle domain id, 10007 for Miden. `attesters` (optional) lists the
deposit attester public keys to allowlist at build time, each as the hex string of the key's 33 compressed SEC1 bytes
(`02` or `03` followed by the x coordinate); when empty or absent the allowlist is seeded later through `set_attester`
notes.

`verification_base_fee` is baked into the faucet's fee schedule and MUST equal the `--verification-base-fee` passed to
`build`; the tool cannot enforce this.

## Nonces file

`nonces.json`, from `nonces.template.json`; unknown fields rejected; the list is required and must not be empty:

```json
{
  "used_nonces": ["0x5585... (32 bytes of hex)"]
}
```

The Circle deposit nonces whose deposits the genesis state already honours; the prefunded balance is backed by them. The
faucet records them as consumed, so the relayer cannot mint them a second time.

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
