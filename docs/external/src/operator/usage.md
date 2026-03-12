---
sidebar_position: 4
---

# Configuration and Usage

As outlined in the [Architecture](./architecture) chapter, the node consists of several components which can be run
separately or as a single bundled process. At present, the recommended way to operate a node is in bundled mode and is
what this guide will focus on. Operating the components separately is very similar and should be relatively
straight-forward to derive from these instructions.

This guide focuses on basic usage. To discover more advanced options we recommend exploring the various help menus
which can be accessed by appending `--help` to any of the commands.

## Bootstrapping

The first step in starting a new Miden network is to initialize the genesis block data. This is a
one-off operation using the `bootstrap` command and by default the genesis block will contain a single
faucet account.

```sh
# Create a folder to store the node's data.
mkdir data

# Bootstrap the node.
#
# This creates the node's database and initializes it with the genesis data.
#
# The genesis block currently contains a single public faucet account. The
# secret for this account is stored in the `<accounts-directory/account.mac>`
# file. This file is not used by the node and should instead by used wherever
# you intend to operate this faucet account.
#
# For example, you could operate a public faucet using our faucet reference
# implementation whose operation is described in a later section.
miden-node bundled bootstrap \
  --data-directory data \
  --accounts-directory .
```

You can also configure the account and asset data in the genesis block by passing in a toml configuration file.
This is particularly useful for setting up test scenarios without requiring multiple rounds of
transactions to achieve the desired state. Any account secrets will be written to disk inside the
the provided `--accounts-directory` path in the process.

```sh
miden-node bundled bootstrap \
  --data-directory data \
  --accounts-directory . \
  --genesis-config-file genesis.toml
```

The genesis configuration file should contain fee parameters, optionally a custom native faucet,
optionally other fungible faucets, and also optionally, wallet definitions with assets, for example:

```toml
# The UNIX timestamp of the genesis block. It will influence the hash of the genesis block.
timestamp = 1717344256
# Defines the format of the block protocol to use for the genesis block.
version   = 1

# The native faucet defaults to a MIDEN token (symbol="MIDEN", decimals=6,
# max_supply=100_000_000_000_000_000). To override it with a pre-built account
# file, specify the path:
#
#   native_faucet = "path/to/faucet.mac"
#
# The path is relative to this configuration file.

# The fee parameters to use for the genesis block.
[fee_parameters]
verification_base_fee = 0

# Another fungible faucet (optional) to initialize at genesis.
[[fungible_faucet]]
# The token symbol to use for the token
symbol       = "FUZZY"
# Number of decimals your token will have, it effectively defines the fixed point accuracy.
decimals     = 6
# Total supply, in _base units_
#
# e.g. a max supply of `1e15` _base units_ and decimals set to `6`, will yield you a total supply
# of `1e15/1e6 = 1e9` `FUZZY`s.
max_supply   = 1_000_000_000_000_000
# Storage mode of the faucet account.
storage_mode = "public"


[[wallet]]
# List of all assets the account should hold. Each token type _must_ have a corresponding faucet.
# The number is in _base units_, e.g. specifying `999 FUZZY` at 6 decimals would become
# `999_000_000`.
assets       = [{ amount = 999_000_000, symbol = "FUZZY" }]
# Storage mode of the wallet account.
storage_mode = "private"
# The code of the account can be updated or not.
# has_updatable_code = false # default value
```

To include pre-built accounts (e.g. bridge or wrapped-asset faucets) in the genesis block, use
`[[account]]` entries with paths to `.mac` files:

```toml
[[account]]
path = "bridge.mac"

[[account]]
path = "eth_faucet.mac"
```

## Operation

Start the node with the desired public gRPC server address.

```sh
miden-node bundled start \
  --data-directory data \
  --rpc.url http://0.0.0.0:57291
```

### gRPC server limits and timeouts

The RPC component enforces per-request timeouts, per-IP rate limits, and global concurrency caps. Configure these
settings for bundled or standalone RPC with the following options:

- `--grpc.timeout` (default `10s`): Maximum request duration before the server drops the request.
- `--grpc.max_connection_age` (default `30m`): Maximum lifetime of a connection before the server closes it.
- `--grpc.burst_size` (default `128`): Per-IP burst capacity before rate limiting kicks in.
- `--grpc.replenish_per_sec` (default `16`): Per-IP request credits replenished per second.
- `--grpc.max_global_connections` (default `1000`): Maximum concurrent gRPC connections across all clients.

## Systemd

Our [Debian packages](./installation.md#debian-package) install a systemd service which operates the node in `bundled`
mode. You'll still need to run the [bootstrapping](#bootstrapping) process before the node can be started.

You can inspect the service file with `systemctl cat miden-node` or alternatively you can see it in
our repository in the `packaging` folder. For the bootstrapping process be sure to specify the data-directory as
expected by the systemd file.

## RocksDB tuning

The store uses RocksDB for the account and nullifier trees, one instance each. The two most impactful knobs per tree
are exposed as CLI flags (also available as environment variables):

| Flag | Default | Notes |
|---|---|---|
| `--account_tree.rocksdb.max_cache_size` | 2 GiB | Shared LRU block cache. Increase on memory-rich hosts. |
| `--account_tree.rocksdb.max_open_fds` | 64 | Raise to 512+ when `ulimit -n` allows. |
| `--nullifier_tree.rocksdb.max_cache_size` | 2 GiB | Same as above for the nullifier tree. |
| `--nullifier_tree.rocksdb.max_open_fds` | 64 | Same as above for the nullifier tree. |

Compaction parallelism is set automatically to the number of available CPU cores.

```sh
miden-node bundled start \
  --data-directory data \
  --rpc.url http://0.0.0.0:57291 \
  --account_tree.rocksdb.max_cache_size 4294967296 \
  --account_tree.rocksdb.max_open_fds 512 \
  --nullifier_tree.rocksdb.max_cache_size 4294967296 \
  --nullifier_tree.rocksdb.max_open_fds 512
```

## Environment variables

Most configuration options can also be configured using environment variables as an alternative to providing the values
via the command-line. This is useful for certain deployment options like `docker` or `systemd`, where they can be easier
to define or inject instead of changing the underlying command line options.

These are especially convenient where multiple different configuration profiles are used. Write the environment
variables to some specific `profile.env` file and load it as part of the node command:

```sh
source profile.env && miden-node <...>
```

This works well on Linux and MacOS, but Windows requires some additional scripting unfortunately.

See the `.env` files in each of the binary crates' [directories](https://github.com/0xMiden/node/tree/next/bin) for a list of all available environment variables.
