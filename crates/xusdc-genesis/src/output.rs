//! The `.mac` file boundary — reading account files and writing them without ever overwriting —
//! the well-known file names every command works with in the current directory, and the stdout
//! id listings.

use std::fmt::Write as _;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::Path;

use anyhow::{Context, Result};
use miden_objects::account_file::AccountFile;
use miden_protocol::account::{Account, AccountId};
use miden_protocol::address::NetworkId;
use xusdc_encoding::xreserve::encoding::EthEmbeddedAccountId;

use crate::config::{GenesisToolConfig, Role};

/// The faucet config `faucet` reads (a filled copy of the crate's `config.template.json`).
pub const CONFIG_FILE: &str = "config.json";

/// The nonces file `record-nonces` reads.
pub const NONCES_FILE: &str = "nonces.json";

/// The fresh distributor `new-distributor` writes and `prefund` reads.
pub const DISTRIBUTOR_MAC_FILE: &str = "distributor.mac";

/// The faucet `faucet` writes and `prefund` / `record-nonces` read.
pub const FAUCET_MAC_FILE: &str = "usdcx-faucet.mac";

/// The prefunded distributor `prefund` writes: the `path` of its `[[account]]` entry in the
/// network operator's genesis config, and the funding service's account file.
pub const GENESIS_DISTRIBUTOR_MAC_FILE: &str = "distributor.genesis.mac";

/// The faucet with the deposit nonces recorded that `record-nonces` writes: the value of the
/// `native_faucet` key in the network operator's genesis config.
pub const GENESIS_FAUCET_MAC_FILE: &str = "usdcx-faucet.genesis.mac";

/// Writes `file` to `path`, refusing to overwrite an existing file. A file carrying secret keys
/// is created readable by its owner only.
pub fn write_account_file(file: &AccountFile, path: &Path) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if !file.auth_secret_keys().is_empty() {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options
        .open(path)
        .with_context(|| {
            format!(
                "creating {} (an existing file is never overwritten)",
                path.display()
            )
        })?
        .write_all(&file.to_bytes())
        .with_context(|| format!("writing {}", path.display()))
}

/// Reads the account file at `path`.
pub fn read_account_file(path: &Path) -> Result<AccountFile> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    AccountFile::try_from_bytes(&bytes)
        .with_context(|| format!("{} is not an account file", path.display()))
}

/// Renders an account id under `label`: hex, its bech32 form on each network, and its bytes32
/// form (the id as an xReserve wire field, e.g. the deposit's `remoteRecipient`).
pub fn render_ids(label: &str, id: AccountId) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "{label}");
    let _ = writeln!(out, "  hex:     {}", id.to_hex());
    let _ = writeln!(out, "  mainnet: {}", id.to_bech32(NetworkId::Mainnet));
    let _ = writeln!(out, "  testnet: {}", id.to_bech32(NetworkId::Testnet));
    let _ = writeln!(out, "  devnet:  {}", id.to_bech32(NetworkId::Devnet));
    let _ = writeln!(
        out,
        "  bytes32: 0x{}",
        hex::encode(EthEmbeddedAccountId::from_account_id(id).to_bytes32())
    );
    out
}

/// Renders the `faucet` listing: the faucet ids, then the configured role ids echoed back.
pub fn render_listing(faucet: &Account, config: &GenesisToolConfig) -> String {
    let mut out = render_ids(&format!("usdcx-faucet ({FAUCET_MAC_FILE})"), faucet.id());
    let _ = writeln!(out, "role accounts:");
    for role in Role::ALL {
        let members: Vec<String> = config
            .accounts
            .get(role)
            .iter()
            .map(|id| id.to_hex())
            .collect();
        let _ = writeln!(out, "  {}: {}", role.as_str(), members.join(", "));
    }
    out
}
