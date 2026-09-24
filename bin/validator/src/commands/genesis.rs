use std::path::PathBuf;

use anyhow::Context;
use miden_node_store::genesis::config::{AccountFileWithName, GenesisConfig, GenesisInputs};
use miden_node_utils::fs::ensure_empty_directory;
use miden_objects::account_file::AccountFile;
use miden_protocol::block::{FeeParameters, ValidatorConfig};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::PublicKey;
use miden_protocol::utils::serde::Serializable;

/// Name of the genesis block file written to the genesis block directory.
const GENESIS_BLOCK_FILE_NAME: &str = "genesis.dat";

/// Inputs used to build the genesis block.
#[derive(clap::Args, Debug)]
pub struct GenesisCommand {
    /// Directory in which to write the genesis block.
    #[arg(long, value_name = "DIR")]
    pub genesis_block_directory: PathBuf,
    /// Directory in which to write generated account files.
    #[arg(long, value_name = "DIR")]
    pub accounts_directory: PathBuf,
    /// TOML file containing additional accounts.
    #[arg(long, env = "MIDEN_VALIDATOR_GENESIS_ACCOUNTS_CONFIG", value_name = "FILE")]
    pub accounts_config: Option<PathBuf>,
    /// Account file for the native fungible faucet.
    #[arg(long, env = "MIDEN_VALIDATOR_GENESIS_NATIVE_FAUCET", value_name = "FILE")]
    pub native_faucet: PathBuf,
    /// Account file for the public funding account.
    #[arg(long, env = "MIDEN_VALIDATOR_GENESIS_FUNDING_ACCOUNT", value_name = "FILE")]
    pub funding_account: PathBuf,
    /// Verification base fee in base units of the native asset.
    #[arg(long, env = "MIDEN_VALIDATOR_GENESIS_VERIFICATION_BASE_FEE")]
    pub verification_base_fee: u32,
    /// Genesis timestamp in seconds since the Unix epoch.
    #[arg(long, env = "MIDEN_VALIDATOR_GENESIS_TIMESTAMP")]
    pub timestamp: u32,
    /// Hex-encoded public keys of all genesis validators. Repeat the flag for each validator. The
    /// environment variable accepts a comma-separated list.
    #[arg(
        long = "validator.key",
        env = super::ENV_GENESIS_VALIDATOR_KEYS,
        value_name = "VALIDATOR_PUBLIC_KEY",
        value_delimiter = ',',
        required = true,
        value_parser = super::parse_validator_public_key
    )]
    pub validator_keys: Vec<PublicKey>,
}

impl GenesisCommand {
    /// Builds the unsigned genesis block and writes generated account files.
    pub fn execute(self) -> anyhow::Result<()> {
        let Self {
            genesis_block_directory,
            accounts_directory,
            accounts_config,
            native_faucet,
            funding_account,
            verification_base_fee,
            timestamp,
            validator_keys,
        } = self;
        for directory in [&genesis_block_directory, &accounts_directory] {
            ensure_empty_directory(directory)?;
        }

        let quorum = u16::try_from(validator_keys.len()).context("too many genesis validators")?;
        let validator_config = ValidatorConfig::new(validator_keys, quorum)
            .context("invalid genesis validator set")?;

        let config = accounts_config
            .as_ref()
            .map(|file_path| {
                GenesisConfig::read_toml_file(file_path).with_context(|| {
                    format!("failed to parse additional accounts from file {}", file_path.display())
                })
            })
            .transpose()?
            .unwrap_or_default();

        let native_faucet = AccountFile::read(&native_faucet)
            .with_context(|| {
                format!("failed to read native faucet from {}", native_faucet.display())
            })?
            .into_parts()
            .0;
        let funding_account = AccountFile::read(&funding_account)
            .with_context(|| {
                format!("failed to read funding account from {}", funding_account.display())
            })?
            .into_parts()
            .0;
        let (genesis_state, accounts) = config.into_state(GenesisInputs {
            native_faucet,
            funding_account,
            fee_parameters: FeeParameters::new(verification_base_fee),
            timestamp,
            validator_config,
        })?;

        for item in accounts.as_account_files(&genesis_state) {
            let AccountFileWithName { account_file, name } = item?;
            let account_path = accounts_directory.join(name);
            // Do not override existing account files.
            fs_err::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&account_path)
                .context("account file already exists")?;
            account_file.write(account_path)?;
        }

        let genesis_block =
            genesis_state.into_block().context("failed to build the genesis block")?;

        let genesis_block_path = genesis_block_directory.join(GENESIS_BLOCK_FILE_NAME);
        fs_err::write(&genesis_block_path, genesis_block.to_bytes())
            .context("failed to write genesis block")?;

        println!("Genesis block written to {}.", genesis_block_path.display());
        println!();
        for account in genesis_block.inner().body().updated_accounts() {
            let account_id = account.account_id();
            let name = &accounts.names[&account_id];
            println!("{name} account id: {}", account_id.to_hex());
        }
        println!();
        println!("Seed each validator's database with:");
        println!();
        println!(
            "  miden-validator bootstrap --data-directory <DIR> --genesis {}",
            genesis_block_path.display()
        );

        Ok(())
    }
}

#[cfg(test)]
pub(super) mod tests {
    use std::path::Path;

    use miden_node_utils::genesis::read_genesis_block;
    use miden_testing::{Auth, MockChainBuilder};

    use super::*;

    pub(crate) fn command(
        root: &Path,
        validator_keys: Vec<PublicKey>,
    ) -> anyhow::Result<GenesisCommand> {
        let mut builder = MockChainBuilder::new();
        let funding_account = builder.add_existing_wallet(Auth::basic_ecdsa())?;
        let native_faucet = builder.add_existing_basic_faucet(
            Auth::basic_ecdsa(),
            "USDCX",
            1_000_000,
            Some(1_000),
        )?;
        let funding_path = root.join("funding.mac");
        let faucet_path = root.join("native.mac");
        AccountFile::new(funding_account, vec![]).write(&funding_path)?;
        AccountFile::new(native_faucet, vec![]).write(&faucet_path)?;
        Ok(GenesisCommand {
            genesis_block_directory: root.join("genesis"),
            accounts_directory: root.join("accounts"),
            accounts_config: None,
            native_faucet: faucet_path,
            funding_account: funding_path,
            verification_base_fee: 7,
            timestamp: 1_717_344_256,
            validator_keys,
        })
    }

    #[test]
    fn genesis_imports_required_accounts_and_exports_additional_wallets() -> anyhow::Result<()> {
        let root = tempfile::tempdir()?;
        let key = miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey::new().public_key();
        let mut command = command(root.path(), vec![key])?;
        let native_id = AccountFile::read(&command.native_faucet)?.account().id();
        let funding = AccountFile::read(&command.funding_account)?.account().clone();
        let config = root.path().join("extra.toml");
        fs_err::write(
            &config,
            "[[wallet]]\nname = 'extra'\naccount_type = 'public'\nassets = [{ symbol = 'USDCX', amount = 40 }]\n",
        )?;
        command.accounts_config = Some(config);
        command.execute()?;
        let genesis = read_genesis_block(&root.path().join("genesis/genesis.dat"))?;
        assert_eq!(genesis.protocol_config().fee_asset_id().faucet_id(), native_id);
        assert_eq!(genesis.inner().header().fee_parameters().verification_base_fee(), 7);
        assert_eq!(genesis.inner().header().timestamp(), 1_717_344_256);
        assert!(genesis.inner().body().updated_accounts().iter().any(|update| {
            update.account_id() == funding.id()
                && update.final_state_commitment() == funding.to_commitment()
        }));
        let extra = AccountFile::read(root.path().join("accounts/extra.mac"))?;
        assert_eq!(
            extra
                .account()
                .vault()
                .get_balance(miden_protocol::asset::AssetId::new_fungible(native_id))?
                .as_u64(),
            40
        );
        assert_eq!(extra.auth_secret_keys().len(), 1);
        Ok(())
    }
}
