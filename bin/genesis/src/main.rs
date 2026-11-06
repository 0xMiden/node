//! `miden-genesis` builds a network's genesis offline: first the genesis xUSDC faucet and its
//! distributor as `.mac` account files, then the genesis block that commits to them. The five
//! commands, in launch order:
//!
//! ```text
//! miden-genesis new-distributor [--auth-scheme <scheme>]        # distributor.mac, .secret
//! miden-genesis faucet --owner <id> --token-supply <n> ...      # usdcx-faucet.mac
//! miden-genesis prefund [--faucet F] [--distributor D]          # distributor.genesis.mac
//! miden-genesis record-nonces --nonce <hex> ... [--faucet F]    # usdcx-faucet.genesis.mac
//! miden-genesis build --genesis-block-directory <dir> ...       # <dir>/genesis.dat
//! ```
//!
//! Exit 0 means every output file was written. No command overwrites an existing file.

use clap::Parser;
use miden_genesis::cli::Cli;

fn main() -> anyhow::Result<()> {
    Cli::parse().run()
}
