# Miden Genesis

A tool for generating canonical Miden genesis accounts and configuration.

## Usage

Generate all genesis accounts with fresh keypairs:

```bash
miden-genesis --output-dir ./genesis
```

Provide existing Falcon512 public keys (both must be specified together):

```bash
miden-genesis --output-dir ./genesis \
  --bridge-admin-public-key <HEX> \
  --ger-manager-public-key <HEX>
```

## Output

The tool generates the following files in the output directory:

- `bridge_admin.mac` - Bridge admin wallet (nonce=0, deployed later via transaction)
- `ger_manager.mac` - GER manager wallet (nonce=0, deployed later via transaction)
- `bridge.mac` - AggLayer bridge account (nonce=1, included in genesis block)
- `genesis.toml` - Genesis configuration referencing only `bridge.mac`

When public keys are omitted, the `.mac` files for bridge admin and GER manager include generated secret keys. When public keys are provided, no secret keys are included.

The bridge account always uses NoAuth and has no secret keys.

## Bootstrapping a node

```bash
# 1. Generate genesis accounts
miden-genesis --output-dir ./genesis

# 2. Bootstrap the genesis block
miden-node validator bootstrap \
  --genesis-block-directory ./data \
  --accounts-directory ./accounts \
  --genesis-config-file ./genesis/genesis.toml \
  --validator.key.hex <validator_key>

# 3. Bootstrap the store
miden-node store bootstrap --data-directory ./data

# 4. Start the node
miden-node bundled start --data-directory ./data ...
```

## TODO

- Support ECDSA (secp256k1) public keys in addition to Falcon512 (e.g. `--bridge-admin-public-key ecdsa:<HEX>`)

## License

This project is [MIT licensed](../../LICENSE).
