//! Account and signing-key files, their output names, and account ID listings.
//!
//! Existing files are never overwritten, and files containing secret keys are owner-only.

use std::fmt::Write as _;
use std::io::Write as _;
use std::path::Path;

use anyhow::{Context, Result};
use fs_err::OpenOptions;
use miden_objects::account_file::AccountFile;
use miden_protocol::account::auth::AuthSecretKey;
use miden_protocol::account::{Account, AccountId};
use miden_protocol::address::NetworkId;
use miden_protocol::utils::serde::Serializable;
use miden_usdcx::xreserve::encoding::EthEmbeddedAccountId;

use crate::config::{GenesisToolConfig, Role};

/// The faucet config `faucet` reads (a filled copy of the crate's `config.template.json`).
pub const CONFIG_FILE: &str = "config.json";

/// The nonces file `record-nonces` reads.
pub const NONCES_FILE: &str = "nonces.json";

/// The fresh distributor `new-distributor` writes and `prefund` reads.
pub const DISTRIBUTOR_MAC_FILE: &str = "distributor.mac";

/// The standalone signing key used by the funding service at startup.
pub const DISTRIBUTOR_SECRET_FILE: &str = "distributor.secret";

/// The faucet `faucet` writes and `prefund` / `record-nonces` read.
pub const FAUCET_MAC_FILE: &str = "usdcx-faucet.mac";

/// The prefunded distributor `prefund` writes: the `path` of its `[[account]]` entry in the network
/// operator's genesis config.
pub const GENESIS_DISTRIBUTOR_MAC_FILE: &str = "distributor.genesis.mac";

/// The faucet with the deposit nonces recorded that `record-nonces` writes: the value of the
/// `native_faucet` key in the network operator's genesis config.
pub const GENESIS_FAUCET_MAC_FILE: &str = "usdcx-faucet.genesis.mac";

/// Writes `file` to `path`, refusing to overwrite an existing file. A file carrying secret keys is
/// created readable by its owner only.
pub fn write_account_file(file: &AccountFile, path: &Path) -> Result<()> {
    write_file(&file.to_bytes(), path, !file.auth_secret_keys().is_empty())
}

/// Writes a serialized signing key in an owner-only file without overwriting existing data.
pub fn write_signing_key(key: &AuthSecretKey, path: &Path) -> Result<()> {
    write_file(&key.to_bytes(), path, true)
}

fn write_file(bytes: &[u8], path: &Path, contains_secret: bool) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if contains_secret {
        use fs_err::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options
        .open(path)
        .context("an existing file is never overwritten")?
        .write_all(bytes)?;
    Ok(())
}

/// Reads the account file at `path`.
pub fn read_account_file(path: &Path) -> Result<AccountFile> {
    fs_err::read(path).map_err(anyhow::Error::from).and_then(|bytes| {
        AccountFile::try_from_bytes(&bytes)
            .with_context(|| format!("{} is not an account file", path.display()))
    })
}

/// Renders an account id under `label`: hex, its bech32 form on each network, and its bytes32 form
/// (the id as an xReserve wire field, e.g. the deposit's `remoteRecipient`).
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
        let members: Vec<String> = config.accounts.get(role).iter().map(|id| id.to_hex()).collect();
        let _ = writeln!(out, "  {}: {}", role.as_str(), members.join(", "));
    }
    out
}
