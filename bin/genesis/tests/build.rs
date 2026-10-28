//! The `build` command: the genesis block it writes and the directories it refuses.

use std::path::{Path, PathBuf};

use miden_genesis::build::BuildCommand;
use miden_node_utils::genesis::read_genesis_block;
use miden_objects::account_file::AccountFile;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::{PublicKey, SigningKey};
use miden_testing::{Auth, MockChainBuilder};

/// Writes a native faucet and a funding wallet under `root` and returns a command that builds the
/// genesis block from them into `root/genesis` and `root/accounts`.
fn command(root: &Path, validator_keys: Vec<PublicKey>) -> anyhow::Result<BuildCommand> {
    let mut builder = MockChainBuilder::new();
    let funding_account = builder.add_existing_wallet(Auth::basic_ecdsa())?;
    let native_faucet =
        builder.add_existing_basic_faucet(Auth::basic_ecdsa(), "USDCX", 1_000_000, Some(1_000))?;
    let funding_path = root.join("funding.mac");
    let faucet_path = root.join("native.mac");
    AccountFile::new(funding_account, vec![]).write(&funding_path)?;
    AccountFile::new(native_faucet, vec![]).write(&faucet_path)?;
    Ok(BuildCommand {
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

fn genesis_file(root: &Path) -> PathBuf {
    root.join("genesis").join("genesis.dat")
}

#[test]
fn build_imports_required_accounts_and_exports_additional_wallets() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let key = SigningKey::new().public_key();
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

    let genesis = read_genesis_block(&genesis_file(root.path()))?;
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

#[test]
fn build_refuses_a_non_empty_genesis_directory() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let key = SigningKey::new().public_key();
    let command = command(root.path(), vec![key])?;
    fs_err::create_dir(&command.genesis_block_directory)?;
    fs_err::write(command.genesis_block_directory.join("stale"), b"")?;

    let error = command.execute().expect_err("a non-empty genesis directory must be rejected");
    assert!(format!("{error:#}").contains("is not empty"), "{error:#}");
    assert!(!genesis_file(root.path()).exists());
    Ok(())
}
