use std::io::Write;
use std::path::Path;

use assert_matches::assert_matches;
use miden_protocol::ONE;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey;
use miden_protocol::crypto::dsa::falcon512_poseidon2::SecretKey;
use miden_protocol::utils::serde::Deserializable;

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Helper to write TOML content to a file and return the path
fn write_toml_file(dir: &Path, content: &str) -> std::path::PathBuf {
    let path = dir.join("genesis.toml");
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(content.as_bytes()).unwrap();
    path
}

/// A validator set holding a single fixed test key, for tests exercising unrelated config features.
fn dev_validator_config() -> ValidatorConfig {
    let key = SigningKey::read_from_bytes(&[7; 32])
        .expect("test signing key should decode")
        .public_key();
    ValidatorConfig::new(vec![key], 1).expect("a single test key is a valid validator set")
}

#[test]
#[miden_node_test_macro::enable_logging]
fn parsing_yields_expected_default_values() -> TestResult {
    // Copy sample file to temp dir since read_toml_file needs a real file path
    let temp_dir = tempfile::tempdir()?;
    let config_path = write_toml_file(temp_dir.path(), include_str!("./samples/01-simple.toml"));

    let gcfg = GenesisConfig::read_toml_file(&config_path)?;
    let (state, _secrets) = gcfg.into_state(dev_validator_config())?;
    let _ = state;
    // Faucets, then the generated faucet operator, then the wallet accounts.
    let native_faucet = state.accounts[0].clone();
    let _excess = state.accounts[1].clone();
    let _faucet_operator = state.accounts[2].clone();
    let wallet1 = state.accounts[3].clone();
    let wallet2 = state.accounts[4].clone();

    assert!(FungibleFaucet::try_from(&native_faucet).is_ok());
    assert!(FungibleFaucet::try_from(&wallet1).is_err());
    assert!(FungibleFaucet::try_from(&wallet2).is_err());

    assert_eq!(native_faucet.nonce(), ONE);
    assert_eq!(wallet1.nonce(), ONE);
    assert_eq!(wallet2.nonce(), ONE);

    {
        let faucet = FungibleFaucet::try_from(native_faucet.storage()).unwrap();

        assert_eq!(faucet.max_supply().as_u64(), 100_000_000_000_000_000);
        assert_eq!(faucet.decimals(), 6);
        assert_eq!(*faucet.symbol(), TokenSymbol::new("MIDEN").unwrap());
    }

    // check account balance, and ensure ordering is retained
    let faucet_vault_key = miden_protocol::asset::AssetId::new_fungible(native_faucet.id());
    assert_matches!(wallet1.vault().get_balance(faucet_vault_key), Ok(val) => {
        assert_eq!(val.as_u64(), 999_000);
    });
    assert_matches!(wallet2.vault().get_balance(faucet_vault_key), Ok(val) => {
        assert_eq!(val.as_u64(), 777);
    });

    // check total issuance of the faucet
    let faucet = FungibleFaucet::try_from(native_faucet.storage()).unwrap();
    assert_eq!(
        faucet.token_supply().as_u64(),
        DEFAULT_FAUCET_OPERATOR_BALANCE + 999_777,
        "Issuance mismatch"
    );

    Ok(())
}

#[test]
fn validator_set_is_committed_to_genesis() -> TestResult {
    let toml = r"
version = 1
timestamp = 1717344256

[fee_parameters]
verification_base_fee = 0
";

    let validator_config = ValidatorConfig::new(
        vec![SigningKey::new().public_key(), SigningKey::new().public_key()],
        2,
    )?;
    let gcfg = GenesisConfig::read_toml(toml, Path::new("."))?;
    let (state, _) = gcfg.into_state(validator_config.clone())?;
    assert_eq!(state.validator_config, validator_config);
    let block = state.into_block()?;
    assert!(block.inner().signatures().is_empty());

    Ok(())
}

#[tokio::test]
#[miden_node_test_macro::enable_logging]
async fn genesis_accounts_have_nonce_one() -> TestResult {
    let gcfg = GenesisConfig::default();
    let (state, secrets) = gcfg.into_state(dev_validator_config()).unwrap();

    // The default configuration generates the native faucet and its operator.
    let account_files = secrets.as_account_files(&state).collect::<Result<Vec<_>, _>>()?;
    assert_eq!(account_files.len(), 2);
    for AccountFileWithName { account_file, name } in account_files {
        assert_eq!(account_file.account.nonce(), ONE, "{name} should be deployed at genesis");
    }

    let _block = state.into_block()?;
    Ok(())
}

#[test]
fn parsing_account_from_file() -> TestResult {
    use miden_protocol::account::auth::AuthScheme;
    use miden_protocol::account::{AccountFile, AccountType};
    use miden_standards::account::auth::Approver;
    use miden_standards::account::wallets::create_basic_wallet;
    use tempfile::tempdir;

    // Create a temporary directory for our test files
    let temp_dir = tempdir()?;
    let config_dir = temp_dir.path();

    // Create a test wallet account and save it to a .mac file
    let init_seed: [u8; 32] = rand::random();
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(rand::random());
    let secret_key = SecretKey::with_rng(&mut rng);
    let auth = Approver::new(secret_key.public_key().into(), AuthScheme::Falcon512Poseidon2);

    let test_account = create_basic_wallet(init_seed, auth, AccountType::Public)?;

    let account_id = test_account.id();

    // Save to file
    let account_file_path = config_dir.join("test_account.mac");
    let account_file = AccountFile::new(test_account, vec![]);
    account_file.write(&account_file_path)?;

    // Create a genesis config TOML that references the account file
    let toml_content = r#"
timestamp = 1717344256
version   = 1

[fee_parameters]
verification_base_fee = 0

[[account]]
path = "test_account.mac"
"#;
    let config_path = write_toml_file(config_dir, toml_content);

    // Parse the config
    let gcfg = GenesisConfig::read_toml_file(&config_path)?;

    // Convert to state and verify the account is included
    let (state, _secrets) = gcfg.into_state(dev_validator_config())?;
    assert!(state.accounts.iter().any(|a| a.id() == account_id));

    Ok(())
}

#[test]
fn generated_native_faucet_is_a_network_account_owned_by_an_operator() -> TestResult {
    use miden_protocol::account::StorageMapKey;
    use miden_standards::account::access::Ownable2Step;
    use miden_standards::account::auth::AuthNetworkAccount;
    use miden_standards::account::fees::FeePolicyManager;

    let gcfg = GenesisConfig::default();
    let (state, secrets) = gcfg.into_state(dev_validator_config())?;

    // The native faucet is the fee faucet and precedes every other account.
    let native_faucet = &state.accounts[0];
    assert_eq!(native_faucet.id(), state.protocol_config.fee_asset_id().faucet_id());
    assert!(FungibleFaucet::try_from(native_faucet).is_ok());
    assert_eq!(native_faucet.nonce(), ONE);

    // Both accounts are written out, but a network account is authenticated by the network and
    // carries no key of its own, so only the operator has one.
    let find = |file_name| {
        secrets
            .secrets
            .iter()
            .find(|(name, ..)| name == file_name)
            .unwrap_or_else(|| panic!("{file_name} should be generated"))
    };
    assert_eq!(secrets.secrets.len(), 2);
    let (_, faucet_id, faucet_secret) = find(NATIVE_FAUCET_FILE_NAME);
    let (_, operator_id, operator_secret) = find(FAUCET_OPERATOR_FILE_NAME);
    assert_eq!(*faucet_id, native_faucet.id());
    assert!(faucet_secret.is_none());
    assert!(operator_secret.is_some());
    assert_ne!(*operator_id, native_faucet.id());

    // The operator is deployed alongside the faucet.
    let operator = state
        .accounts
        .iter()
        .find(|account| account.id() == *operator_id)
        .expect("the operator account is part of the genesis state");
    assert_eq!(operator.nonce(), ONE);
    assert!(FungibleFaucet::try_from(operator).is_err());
    let native_asset_id = miden_protocol::asset::AssetId::new_fungible(native_faucet.id());
    assert_eq!(
        operator.vault().get_balance(native_asset_id)?.as_u64(),
        DEFAULT_FAUCET_OPERATOR_BALANCE,
    );

    // The pre-funded balance is part of the faucet's genesis issuance.
    let faucet = FungibleFaucet::try_from(native_faucet.storage())?;
    assert_eq!(faucet.token_supply().as_u64(), DEFAULT_FAUCET_OPERATOR_BALANCE);

    // The faucet charges fees in its own asset.
    let fee_asset = native_faucet
        .storage()
        .get_item(FeePolicyManager::fee_asset_id_slot())
        .expect("the fee asset slot should exist");
    assert_eq!(
        fee_asset,
        native_asset_id.to_word(),
        "the native faucet's fee asset must reference the faucet itself"
    );

    // The faucet is network authenticated: `AuthNetworkAccount` checks an allowlist of note scripts
    // instead of a signature. Only mint and burn notes are accepted.
    for script_root in [MintNote::script_root(), BurnNote::script_root()] {
        let allowed = native_faucet.storage().get_map_item(
            AuthNetworkAccount::allowed_note_scripts_slot(),
            StorageMapKey::new(script_root.as_word()),
        )?;
        // The allowlist flags an allowed entry as `[1, 0, 0, 0]`.
        assert_eq!(allowed, [ONE, Felt::ZERO, Felt::ZERO, Felt::ZERO].into());
    }

    // Check the operator is the faucet owner and the active mint policy allows the owner only
    let ownership = Ownable2Step::try_from_storage(native_faucet.storage())?;
    assert_eq!(ownership.owner(), Some(*operator_id));
    assert_eq!(
        native_faucet
            .storage()
            .get_item(TokenPolicyManager::active_mint_policy_slot())?,
        MintPolicy::owner_only().root().as_word(),
    );

    Ok(())
}

#[test]
fn parsing_native_faucet_from_file() -> TestResult {
    use miden_protocol::account::auth::AuthScheme;
    use miden_protocol::account::{AccountBuilder, AccountFile, AccountType};
    use miden_protocol::asset::AssetAmount;
    use miden_standards::account::auth::{Approver, AuthSingleSig};
    use miden_standards::account::policies::{BurnPolicy, MintPolicy, TokenPolicyManager};
    use tempfile::tempdir;

    // Create a temporary directory for our test files
    let temp_dir = tempdir()?;
    let config_dir = temp_dir.path();

    // Create a faucet account and save it to a .mac file
    let init_seed: [u8; 32] = rand::random();
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(rand::random());
    let secret_key = SecretKey::with_rng(&mut rng);
    let auth = AuthSingleSig::new(Approver::new(
        secret_key.public_key().into(),
        AuthScheme::Falcon512Poseidon2,
    ));

    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("MIDEN").unwrap())
        .symbol(TokenSymbol::new("MIDEN").unwrap())
        .decimals(6)
        .max_supply(AssetAmount::new(1_000_000_000)?)
        .build()?;

    let faucet_account = AccountBuilder::new(init_seed)
        .account_type(AccountType::Public)
        .with_component(auth)
        .with_component(faucet)
        .with_components(
            TokenPolicyManager::builder()
                .active_mint_policy(MintPolicy::allow_all())
                .active_burn_policy(BurnPolicy::allow_all())
                .build(),
        )
        .build()?;

    let faucet_id = faucet_account.id();

    // Save to file
    let faucet_file_path = config_dir.join("native_faucet.mac");
    let account_file = AccountFile::new(faucet_account, vec![]);
    account_file.write(&faucet_file_path)?;

    // Create a genesis config TOML that references the faucet file
    let toml_content = r#"
timestamp = 1717344256
version   = 1

native_faucet = "native_faucet.mac"

[fee_parameters]
verification_base_fee = 0
"#;
    let config_path = write_toml_file(config_dir, toml_content);

    // Parse the config
    let gcfg = GenesisConfig::read_toml_file(&config_path)?;

    // Convert to state and verify the native faucet is included
    let (state, secrets) = gcfg.into_state(dev_validator_config())?;
    assert!(state.accounts.iter().any(|a| a.id() == faucet_id));

    // No secrets should be generated for file-loaded native faucet
    assert!(secrets.secrets.is_empty());

    Ok(())
}

#[test]
fn native_faucet_from_file_must_be_faucet_type() -> TestResult {
    use miden_protocol::account::auth::AuthScheme;
    use miden_protocol::account::{AccountFile, AccountType};
    use miden_standards::account::auth::Approver;
    use miden_standards::account::wallets::create_basic_wallet;
    use tempfile::tempdir;

    // Create a temporary directory for our test files
    let temp_dir = tempdir()?;
    let config_dir = temp_dir.path();

    // Create a regular wallet account (not a faucet) and try to use it as native faucet
    let init_seed: [u8; 32] = rand::random();
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(rand::random());
    let secret_key = SecretKey::with_rng(&mut rng);
    let auth = Approver::new(secret_key.public_key().into(), AuthScheme::Falcon512Poseidon2);

    let regular_account = create_basic_wallet(init_seed, auth, AccountType::Public)?;

    // Save to file
    let account_file_path = config_dir.join("not_a_faucet.mac");
    let account_file = AccountFile::new(regular_account, vec![]);
    account_file.write(&account_file_path)?;

    // Create a genesis config TOML that tries to use a non-faucet as native faucet
    let toml_content = r#"
timestamp = 1717344256
version   = 1

native_faucet = "not_a_faucet.mac"

[fee_parameters]
verification_base_fee = 0
"#;
    let config_path = write_toml_file(config_dir, toml_content);

    // Parsing should succeed
    let gcfg = GenesisConfig::read_toml_file(&config_path)?;

    // into_state should fail with NativeFaucetNotFungible error when loading the file
    let result = gcfg.into_state(dev_validator_config());
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, GenesisConfigError::NativeFaucetNotFungible { .. }),
        "Expected NativeFaucetNotFungible error, got: {err:?}"
    );

    Ok(())
}

#[test]
fn missing_account_file_returns_error() {
    // Create a genesis config TOML that references a non-existent file
    let toml_content = r#"
timestamp = 1717344256
version   = 1

[fee_parameters]
verification_base_fee = 0

[[account]]
path = "does_not_exist.mac"
"#;

    // Use temp dir as config dir
    let temp_dir = tempfile::tempdir().unwrap();
    let config_path = write_toml_file(temp_dir.path(), toml_content);

    // Parsing should succeed
    let gcfg = GenesisConfig::read_toml_file(&config_path).unwrap();

    // into_state should fail with AccountFileRead error when loading the file
    let result = gcfg.into_state(dev_validator_config());
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, GenesisConfigError::AccountFileRead(..)),
        "Expected AccountFileRead error, got: {err:?}"
    );
}
