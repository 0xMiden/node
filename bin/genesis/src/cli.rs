//! The command-line interface: the five commands in launch order and their handlers.
//!
//! Every account command writes the current directory under the well-known file names, reads its
//! account inputs from there (each can be pointed elsewhere) and never overwrites an existing
//! file. The faucet parameters and the deposit nonces are flags. The `build` command takes
//! explicit directories and account files.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use miden_objects::account_file::AccountFile;
use miden_protocol::account::auth::AuthScheme;
use miden_usdcx::xreserve::encoding::DepositNonce;

use crate::accounts::{build_faucet, new_distributor, prefund_distributor, record_nonces};
use crate::build::BuildCommand;
use crate::config::{GenesisToolConfig, parse_deposit_nonce};
use crate::output::{
    DISTRIBUTOR_MAC_FILE,
    DISTRIBUTOR_SECRET_FILE,
    FAUCET_MAC_FILE,
    GENESIS_DISTRIBUTOR_MAC_FILE,
    GENESIS_FAUCET_MAC_FILE,
    read_account_file,
    render_ids,
    render_listing,
    write_account_file,
    write_signing_key,
};

// CLI
// ================================================================================================

/// Builds the genesis xUSDC faucet and its distributor offline, writes their .mac account files,
/// and builds the genesis block that commits to them.
#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Generates a fresh public basic wallet with a new signing key and writes it, key included, as
    /// distributor.mac (undeployed: nonce zero, empty vault), plus its key as distributor.secret.
    NewDistributor {
        /// The signing scheme of the generated key.
        #[arg(long, value_enum, default_value_t = AuthSchemeArg::EcdsaK256Keccak)]
        auth_scheme: AuthSchemeArg,
    },
    /// Builds the genesis faucet from the faucet parameters and role-account ids and writes it as
    /// usdcx-faucet.mac (nonce one, no seed).
    Faucet {
        #[command(flatten)]
        config: GenesisToolConfig,
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
    /// Records the given Circle deposit nonces as consumed and writes the result as the
    /// genesis-ready usdcx-faucet.genesis.mac.
    RecordNonces {
        /// The faucet file written by `faucet`.
        #[arg(long, default_value = FAUCET_MAC_FILE)]
        faucet: PathBuf,
        /// A consumed deposit nonce as the hex of its 32 bytes; repeat per nonce or separate with
        /// commas. Recording a nonce twice is a no-op.
        #[arg(
            long = "nonce",
            value_name = "NONCE",
            required = true,
            value_delimiter = ',',
            value_parser = parse_deposit_nonce
        )]
        nonces: Vec<DepositNonce>,
    },
    /// Builds the genesis block from the required accounts and optional additional accounts.
    ///
    /// Writes the unsigned genesis block and generated account files to disk. The genesis header
    /// commits to the full validator set. Those validators must sign every subsequent block.
    /// Each service seeds its database from the genesis block with its `bootstrap` command.
    Build(BuildCommand),
}

/// The signing schemes `new-distributor` can generate a key for.
#[derive(Clone, Copy, ValueEnum)]
pub enum AuthSchemeArg {
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

impl Cli {
    /// Runs the parsed command.
    pub fn run(self) -> Result<()> {
        match self.command {
            Command::NewDistributor { auth_scheme } => run_new_distributor(auth_scheme.into()),
            Command::Faucet { config } => run_faucet(&config),
            Command::Prefund { faucet, distributor } => run_prefund(&faucet, &distributor),
            Command::RecordNonces { faucet, nonces } => run_record_nonces(&faucet, &nonces),
            Command::Build(command) => command.execute(),
        }
    }
}

// ACCOUNT COMMANDS
// ================================================================================================

fn run_new_distributor(scheme: AuthScheme) -> Result<()> {
    let distributor = new_distributor(scheme).context("generating the distributor")?;
    write_account_file(&distributor, Path::new(DISTRIBUTOR_MAC_FILE))?;
    write_signing_key(
        distributor
            .auth_secret_keys()
            .first()
            .context("the distributor has no signing key")?,
        Path::new(DISTRIBUTOR_SECRET_FILE),
    )?;
    print!(
        "{}",
        render_ids(
            &format!("distributor ({DISTRIBUTOR_MAC_FILE}, {scheme} key)"),
            distributor.account().id(),
        )
    );
    println!("written to {DISTRIBUTOR_MAC_FILE} and {DISTRIBUTOR_SECRET_FILE}");
    Ok(())
}

fn run_faucet(config: &GenesisToolConfig) -> Result<()> {
    let faucet = build_faucet(config).context("building the genesis faucet")?;
    write_account_file(&AccountFile::new(faucet.clone(), Vec::new()), Path::new(FAUCET_MAC_FILE))?;
    print!("{}", render_listing(&faucet, config));
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

fn run_record_nonces(faucet_path: &Path, nonces: &[DepositNonce]) -> Result<()> {
    let (faucet, _) = read_account_file(faucet_path)?.into_parts();
    let recorded = record_nonces(&faucet, nonces).context("recording the consumed nonces")?;
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

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey;
    use miden_protocol::utils::serde::{Deserializable, Serializable};

    use super::*;

    const BASE_BUILD_ARGS: [&str; 14] = [
        "miden-genesis",
        "build",
        "--genesis-block-directory",
        "/tmp/genesis",
        "--accounts-directory",
        "/tmp/accounts",
        "--native-faucet",
        "/tmp/native-faucet.mac",
        "--funding-account",
        "/tmp/funding-account.mac",
        "--verification-base-fee",
        "7",
        "--timestamp",
        "1717344256",
    ];

    fn parse_build(extra: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(BASE_BUILD_ARGS.iter().copied().chain(extra.iter().copied()))
    }

    #[test]
    fn build_validator_keys_parse_from_repeated_flags() {
        let keys = [7u8, 8].map(|seed| {
            SigningKey::read_from_bytes(&[seed; 32]).expect("test signing key should decode")
        });
        let hex_keys = keys.clone().map(|key| hex::encode(key.public_key().to_bytes()));
        let cli = parse_build(&["--validator.key", &hex_keys[0], "--validator.key", &hex_keys[1]])
            .expect("build with explicit validator keys must parse");
        let Command::Build(command) = cli.command else {
            panic!("expected the build command");
        };
        assert_eq!(command.validator_keys, keys.map(|key| key.public_key()).to_vec());
    }

    #[test]
    fn build_requires_an_explicit_validator_set() {
        let Err(error) = parse_build(&[]) else {
            panic!("build without an explicit validator set must be rejected");
        };
        assert_eq!(error.kind(), clap::error::ErrorKind::MissingRequiredArgument);

        let key = SigningKey::read_from_bytes(&[7; 32]).expect("test signing key should decode");
        let key_hex = hex::encode(key.public_key().to_bytes());
        parse_build(&["--accounts-config", "/tmp/accounts.toml", "--validator.key", &key_hex])
            .expect("additional accounts with an explicit validator set must parse");
    }

    #[test]
    fn build_requires_explicit_accounts_fee_and_timestamp() {
        let key = SigningKey::new();
        let key_hex = hex::encode(key.public_key().to_bytes());
        for flag in
            ["--native-faucet", "--funding-account", "--verification-base-fee", "--timestamp"]
        {
            let position = BASE_BUILD_ARGS.iter().position(|value| *value == flag).unwrap();
            let args = BASE_BUILD_ARGS
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != position && *index != position + 1)
                .map(|(_, value)| *value)
                .chain(["--validator.key", key_hex.as_str()]);
            let Err(error) = Cli::try_parse_from(args) else {
                panic!("build must require {flag}");
            };
            assert_eq!(error.kind(), clap::error::ErrorKind::MissingRequiredArgument, "{flag}");
        }
    }

    #[test]
    fn build_rejects_an_invalid_validator_key() {
        let Err(error) = parse_build(&["--validator.key", "not-hex"]) else {
            panic!("an invalid validator key must be rejected");
        };
        assert_eq!(error.kind(), clap::error::ErrorKind::ValueValidation);
    }

    #[test]
    fn account_commands_parse_with_defaults() {
        for args in [
            vec!["miden-genesis", "new-distributor"],
            vec![
                "miden-genesis",
                "faucet",
                "--owner",
                "0x3cd7940c4946bad179675b1d7d8059",
                "--token-supply",
                "100000000",
                "--verification-base-fee",
                "7",
            ],
            vec!["miden-genesis", "prefund"],
            vec!["miden-genesis", "record-nonces", "--nonce", &"55".repeat(32)],
        ] {
            Cli::try_parse_from(args).expect("account command must parse with its required flags");
        }
    }
}
