# xusdc-genesis

Builds the genesis xUSDC faucet and its distributor **offline** — before any network exists —
and writes their `.mac` account files. The faucet id hashes the account seed plus the code and
storage commitments (no chain state), so the id the tool prints is the id the network boots with,
reproducible from the config. Recording the consumed deposit nonces and prefunding the
distributor are later steps that leave the faucet id unchanged.

The config names the five role holders the `XReserveStablecoinBuilder` seeds — **owner**
(`ADMIN`), **attest_admin**, **pauser**, **unpauser**, **blocklist_manager** — by bare account
id (hex or bech32). At launch the distributor doubles as the bootstrap `ADMIN`: put its id in
`accounts.owner` and leave the operational roles empty; they are assigned once the network runs.

## Install

```sh
cargo install --path crates/xusdc-genesis --locked    # add --force to reinstall after pulling
```

`xusdc-genesis` is then on `PATH`; `cargo run -p xusdc-genesis --` from the repo works the same.

## Usage

Every command works in the current directory: it reads its inputs under their well-known names
(each `--flag` below can point elsewhere) and writes one new file. No command overwrites an
existing file, so a re-run needs the old output moved away first. Start from copies of the
crate's two templates, then run the four commands in launch order:

```sh
cp <repo>/crates/xusdc-genesis/config.template.json config.json    # then replace every <...> value
cp <repo>/crates/xusdc-genesis/nonces.template.json nonces.json    # then list the deposit nonces
xusdc-genesis new-distributor [--auth-scheme ecdsa-k256-keccak|falcon512-poseidon2]
xusdc-genesis faucet [--config config.json]
xusdc-genesis prefund [--faucet usdcx-faucet.mac] [--distributor distributor.mac]
xusdc-genesis record-nonces [--faucet usdcx-faucet.mac] [--nonces nonces.json]
```

1. `new-distributor` generates a fresh public basic wallet with a new signing key (ECDSA
   secp256k1/keccak by default, Falcon512Poseidon2 on request) and writes it, key included, as
   `distributor.mac`: undeployed (nonce zero, empty vault), exactly what a wallet created with
   `miden-client new-wallet --account-type public` and exported with its keys looks like — that
   file is accepted in step 3 too. Prints the distributor id: hex, bech32 for
   mainnet/testnet/devnet, and the bytes32 form that is the deposit's `remoteRecipient` on the
   xReserve side (the id right-aligned in 32 bytes; the layout is `DEV-10`, open with Circle).
   The id goes into `config.json` as `accounts.owner`. Every command prints its ids in the same
   four forms.
2. `faucet` builds the genesis faucet from `config.json` and writes `usdcx-faucet.mac` (nonce
   one, no seed). Prints the faucet id plus the configured role ids. Register this id with Circle
   and make the deposits against it.
3. `prefund` gives the distributor the faucet's whole recorded `token_supply`, promotes it to
   genesis form (nonce one, no seed) and writes it, key included, as `distributor.genesis.mac`.
   It takes no amount: the faucet records the supply as issued, and the distributor's balance
   must equal it (the faucet's burn path is bounded by that counter). The distributor must be
   public, undeployed and carry a signing key; the command runs once per distributor.
4. `record-nonces` records the Circle deposit nonces listed in `nonces.json` as consumed in the
   faucet and writes `usdcx-faucet.genesis.mac`. Recording a nonce twice is a no-op, so the file
   can list every nonce so far. Run it after the deposits, when their nonces are known.

Steps 3 and 4 both read the faucet written by step 2 and are independent of each other.

## Config

`config.template.json` in this crate is the placeholder form: copy it to `config.json` and
replace every `<...>` value (the template does not parse until they are): the distributor id
and the attester key. It pre-fills the faucet seed (the ASCII of `USDCX-FAUCET` zero-padded to
32 bytes: the seed is public and only has to be fixed before `faucet` runs), the launch supply
of 100 USDC, the Miden domain, the min burn amount, the launch `verification_base_fee` of 7,
and the empty operational roles. JSON, unknown fields rejected:

```json
{
  "accounts": {
    "owner":              "0x6aeeb7cba03918516870e95568b77b",
    "attest_admins":      ["0x... or bech32"],
    "pausers":            ["0x... or bech32", "0x... several holders allowed"],
    "unpausers":          ["0x... or bech32"],
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

`accounts.owner` is the single `ADMIN` holder's account id; the four operational role fields
each list zero or more holders (absent means empty — the role is then populated later through
the standard role-action note). Every id is `0x`-prefixed hex or bech32, and every listed
holder is seeded as a member of its role. `faucet.seed`
is the faucet's 32-byte account seed as a hex string (the `0x` prefix is optional on every
byte-string field); `token_supply` is the initial supply in base units (6 decimals, so
`100000000` is 100 USDC) — the amount deposited with Circle for the distributor; it feeds the
faucet id, so it must be final before `faucet` runs. The supply cap is not configurable and is
set to the maximum asset amount; `domain` is the Circle domain id, 10007 for Miden. `attesters`
(optional) lists the deposit attester public keys to allowlist at build time, each as the hex
string of the key's 33 compressed SEC1 bytes (`02` or `03` followed by the x coordinate); when
empty or absent the allowlist is seeded later through `set_attester` notes.

`verification_base_fee` is baked into the faucet's fee schedule and MUST equal the
`[fee_parameters] verification_base_fee` the network operator puts in the node's `genesis.toml`
— the tool cannot enforce this.

## Nonces file

`nonces.json`, from `nonces.template.json`; unknown fields rejected; the list is required and
must not be empty:

```json
{
  "used_nonces": ["0x5585... (32 bytes of hex)"]
}
```

The Circle deposit nonces whose deposits the genesis state already honours — the prefunded
balance is backed by them. The faucet records them as consumed, so the relayer cannot mint them
a second time.

## Node genesis (the network operator's artifact)

The operator's `genesis.toml` takes the two `.genesis.mac` files:

```toml
native_faucet = "usdcx-faucet.genesis.mac"

[[account]]
path = "distributor.genesis.mac"
```

The node takes `[[account]]` files as they are (no validation, no nonce bump), which is why
`prefund` emits the genesis form. Do not list `[[wallet]]` entries holding the xUSDC symbol: the
node would overwrite the faucet's recorded `token_supply` with their total.
`distributor.genesis.mac` carries the distributor's signing key — keep the genesis directory
private; the same file is the funding service's `--account-file`.

The role accounts are NOT injected at genesis — their holders deploy them with their first
transaction.

The `.mac` format follows the protocol version this workspace pins; the node building the
genesis block must be on the same protocol family.
