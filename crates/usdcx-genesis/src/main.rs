//! `miden-usdcx-genesis` — builds the genesis xUSDC faucet and its distributor offline and writes
//! their `.mac` account files. Every command reads and writes the current directory under the
//! well-known file names (each input can be pointed elsewhere). The five commands, in launch
//! order:
//!
//! ```text
//! cargo run -p miden-usdcx-genesis -- new-distributor [--auth-scheme <scheme>]      # writes distributor.mac
//! cargo run -p miden-usdcx-genesis -- faucet [--config config.json]                 # writes usdcx-faucet.mac
//! cargo run -p miden-usdcx-genesis -- prefund [--faucet usdcx-faucet.mac] [--distributor distributor.mac]
//!                                                                                   # writes distributor.genesis.mac
//! cargo run -p miden-usdcx-genesis -- record-nonces [--faucet usdcx-faucet.mac] [--nonces nonces.json]
//!                                                                                   # writes usdcx-faucet.genesis.mac
//! cargo run -p miden-usdcx-genesis -- upgrade-policy-manager [--faucet usdcx-faucet.genesis.mac]
//!                                                                                   # writes usdcx-faucet-v2.genesis.mac
//! ```
//!
//! Exit 0 = the account file written. The id listing goes to stdout. No command overwrites an
//! existing file.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use miden_objects::account_file::AccountFile;
use miden_protocol::account::auth::AuthScheme;
use miden_usdcx_genesis::accounts::{
    build_faucet,
    new_distributor,
    prefund_distributor,
    record_nonces,
    upgrade_policy_manager,
};
use miden_usdcx_genesis::config::{GenesisToolConfig, UsedNoncesFile};
use miden_usdcx_genesis::output::{
    CONFIG_FILE,
    DISTRIBUTOR_MAC_FILE,
    FAUCET_MAC_FILE,
    GENESIS_DISTRIBUTOR_MAC_FILE,
    GENESIS_FAUCET_MAC_FILE,
    GENESIS_FAUCET_V2_MAC_FILE,
    NONCES_FILE,
    read_account_file,
    render_ids,
    render_listing,
    write_account_file,
};

/// Builds the genesis xUSDC faucet and its distributor offline, writes their .mac account files
/// into the current directory, and prints their ids (hex, bech32, bytes32).
#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generates a fresh public basic wallet with a new signing key and writes it, key included, as
    /// distributor.mac (undeployed: nonce zero, empty vault).
    NewDistributor {
        /// The signing scheme of the generated key.
        #[arg(long, value_enum, default_value_t = AuthSchemeArg::EcdsaK256Keccak)]
        auth_scheme: AuthSchemeArg,
    },
    /// Builds the genesis faucet from the config's faucet parameters and role-account ids and
    /// writes it as usdcx-faucet.mac (nonce one, no seed).
    Faucet {
        /// The JSON config (a filled copy of the crate's config.template.json).
        #[arg(long, default_value = CONFIG_FILE)]
        config: PathBuf,
    },
    /// Gives the distributor the faucet's whole recorded token supply and writes it, key included,
    /// as the genesis-ready distributor.genesis.mac (nonce one, no seed).
    Prefund {
        /// The faucet file written by `faucet`.
        #[arg(long, default_value = FAUCET_MAC_FILE)]
        faucet: PathBuf,
        /// The distributor file written by `new-distributor` (or exported from the client).
        #[arg(long, default_value = DISTRIBUTOR_MAC_FILE)]
        distributor: PathBuf,
    },
    /// Records the Circle deposit nonces in the JSON file as consumed and writes the result as the
    /// genesis-ready usdcx-faucet.genesis.mac.
    RecordNonces {
        /// The faucet file written by `faucet`.
        #[arg(long, default_value = FAUCET_MAC_FILE)]
        faucet: PathBuf,
        /// The nonces JSON (see the crate README for the schema).
        #[arg(long, default_value = NONCES_FILE)]
        nonces: PathBuf,
    },
    /// Replaces the faucet's token policy manager with the V2 one, whose transfer policies keep
    /// working while the faucet is paused, and writes the result as the genesis-ready
    /// usdcx-faucet-v2.genesis.mac.
    UpgradePolicyManager {
        /// The faucet file written by `record-nonces`.
        #[arg(long, default_value = GENESIS_FAUCET_MAC_FILE)]
        faucet: PathBuf,
    },
}

/// The signing schemes `new-distributor` can generate a key for.
#[derive(Clone, Copy, ValueEnum)]
enum AuthSchemeArg {
    EcdsaK256Keccak,
    Falcon512Poseidon2,
}

impl From<AuthSchemeArg> for AuthScheme {
    fn from(scheme: AuthSchemeArg) -> Self {
        match scheme {
            AuthSchemeArg::EcdsaK256Keccak => AuthScheme::EcdsaK256Keccak,
            AuthSchemeArg::Falcon512Poseidon2 => AuthScheme::Falcon512Poseidon2,
        }
    }
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::NewDistributor { auth_scheme } => run_new_distributor(auth_scheme.into()),
        Command::Faucet { config } => run_faucet(&config),
        Command::Prefund { faucet, distributor } => run_prefund(&faucet, &distributor),
        Command::RecordNonces { faucet, nonces } => run_record_nonces(&faucet, &nonces),
        Command::UpgradePolicyManager { faucet } => run_upgrade_policy_manager(&faucet),
    }
}

fn run_new_distributor(scheme: AuthScheme) -> Result<()> {
    let distributor = new_distributor(scheme).context("generating the distributor")?;
    write_account_file(&distributor, Path::new(DISTRIBUTOR_MAC_FILE))?;
    print!(
        "{}",
        render_ids(
            &format!("distributor ({DISTRIBUTOR_MAC_FILE}, {scheme} key)"),
            distributor.account().id(),
        )
    );
    println!("written to {DISTRIBUTOR_MAC_FILE}");
    Ok(())
}

fn run_faucet(config_path: &Path) -> Result<()> {
    let config = GenesisToolConfig::load(config_path)
        .with_context(|| format!("loading the config from {}", config_path.display()))?;
    let faucet = build_faucet(&config).context("building the genesis faucet")?;
    write_account_file(&AccountFile::new(faucet.clone(), Vec::new()), Path::new(FAUCET_MAC_FILE))?;
    print!("{}", render_listing(&faucet, &config));
    println!("written to {FAUCET_MAC_FILE}");
    Ok(())
}

fn run_prefund(faucet_path: &Path, distributor_path: &Path) -> Result<()> {
    let (faucet, _) = read_account_file(faucet_path)?.into_parts();
    let distributor = read_account_file(distributor_path)?;
    let prefunded =
        prefund_distributor(&faucet, &distributor).context("prefunding the distributor")?;
    write_account_file(&prefunded, Path::new(GENESIS_DISTRIBUTOR_MAC_FILE))?;
    print!(
        "{}",
        render_ids(
            &format!("distributor ({GENESIS_DISTRIBUTOR_MAC_FILE}, prefunded)"),
            prefunded.account().id(),
        )
    );
    println!(
        "  balance: {} base units of the faucet {}",
        prefunded
            .account()
            .vault()
            .get_balance(miden_protocol::asset::AssetId::new_fungible(faucet.id()))
            .context("reading the prefunded balance")?
            .as_u64(),
        faucet.id().to_hex(),
    );
    println!("written to {GENESIS_DISTRIBUTOR_MAC_FILE}");
    Ok(())
}

fn run_record_nonces(faucet_path: &Path, nonces_path: &Path) -> Result<()> {
    let (faucet, _) = read_account_file(faucet_path)?.into_parts();
    let nonces = UsedNoncesFile::load(nonces_path)
        .with_context(|| format!("loading the nonces from {}", nonces_path.display()))?
        .used_nonces;
    if nonces.is_empty() {
        bail!("{} lists no nonces", nonces_path.display());
    }

    let recorded = record_nonces(&faucet, &nonces).context("recording the consumed nonces")?;
    write_account_file(
        &AccountFile::new(recorded.clone(), Vec::new()),
        Path::new(GENESIS_FAUCET_MAC_FILE),
    )?;
    print!(
        "{}",
        render_ids(
            &format!("usdcx-faucet ({GENESIS_FAUCET_MAC_FILE}, {} nonces recorded)", nonces.len()),
            recorded.id(),
        )
    );
    println!("written to {GENESIS_FAUCET_MAC_FILE}");
    Ok(())
}

fn run_upgrade_policy_manager(faucet_path: &Path) -> Result<()> {
    let (faucet, _) = read_account_file(faucet_path)?.into_parts();
    let upgraded = upgrade_policy_manager(&faucet).context("upgrading the token policy manager")?;
    write_account_file(
        &AccountFile::new(upgraded.clone(), Vec::new()),
        Path::new(GENESIS_FAUCET_V2_MAC_FILE),
    )?;
    print!(
        "{}",
        render_ids(
            &format!("usdcx-faucet ({GENESIS_FAUCET_V2_MAC_FILE}, token policy manager V2)"),
            upgraded.id(),
        )
    );
    println!("written to {GENESIS_FAUCET_V2_MAC_FILE}");
    Ok(())
}
