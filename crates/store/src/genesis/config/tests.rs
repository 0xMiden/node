use std::path::Path;

use assert_matches::assert_matches;
use miden_protocol::ONE;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SecretKey;

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
#[miden_node_test_macro::enable_logging]
fn parsing_yields_expected_default_values() -> TestResult {
    let s = include_str!("./samples/01-simple.toml");
    // Use current directory since this sample doesn't reference any account files
    let gcfg = GenesisConfig::read_toml(s, Path::new("."))?;
    let (state, _secrets) = gcfg.into_state(SecretKey::new())?;
    let _ = state;
    // faucets always precede wallet accounts
    let native_faucet = state.accounts[0].clone();
    let _excess = state.accounts[1].clone();
    let wallet1 = state.accounts[2].clone();
    let wallet2 = state.accounts[3].clone();

    assert!(native_faucet.is_faucet());
    assert!(wallet1.is_regular_account());
    assert!(wallet2.is_regular_account());

    assert_eq!(native_faucet.nonce(), ONE);
    assert_eq!(wallet1.nonce(), ONE);
    assert_eq!(wallet2.nonce(), ONE);

    {
        let faucet = BasicFungibleFaucet::try_from(native_faucet.clone()).unwrap();

        assert_eq!(faucet.max_supply(), Felt::new(100_000_000));
        assert_eq!(faucet.decimals(), 3);
        assert_eq!(faucet.symbol(), TokenSymbol::new("MIDEN").unwrap());
    }

    // check account balance, and ensure ordering is retained
    assert_matches!(wallet1.vault().get_balance(native_faucet.id()), Ok(val) => {
        assert_eq!(val, 999_000);
    });
    assert_matches!(wallet2.vault().get_balance(native_faucet.id()), Ok(val) => {
        assert_eq!(val, 777);
    });

    // check total issuance of the faucet
    assert_eq!(
        native_faucet.storage().get_item(AccountStorage::faucet_sysdata_slot()).unwrap()[3],
        Felt::new(999_777),
        "Issuance mismatch"
    );

    Ok(())
}

#[test]
#[miden_node_test_macro::enable_logging]
fn genesis_accounts_have_nonce_one() -> TestResult {
    let gcfg = GenesisConfig::default();
    let (state, secrets) = gcfg.into_state(SecretKey::new()).unwrap();
    let mut iter = secrets.as_account_files(&state);
    let AccountFileWithName { account_file: status_quo, .. } = iter.next().unwrap().unwrap();
    assert!(iter.next().is_none());

    assert_eq!(status_quo.account.nonce(), ONE);

    let _block = state.into_block()?;
    Ok(())
}

#[test]
fn parsing_account_from_file() -> TestResult {
    use miden_protocol::account::{AccountFile, AccountStorageMode, AccountType};
    use miden_standards::AuthScheme;
    use miden_standards::account::wallets::create_basic_wallet;
    use tempfile::tempdir;

    // Create a temporary directory for our test files
    let temp_dir = tempdir()?;
    let config_dir = temp_dir.path();

    // Create a test wallet account and save it to a .mac file
    let init_seed: [u8; 32] = rand::random();
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(rand::random());
    let secret_key = miden_protocol::crypto::dsa::falcon512_rpo::SecretKey::with_rng(
        &mut miden_node_utils::crypto::get_rpo_random_coin(&mut rng),
    );
    let auth = AuthScheme::Falcon512Rpo { pub_key: secret_key.public_key().into() };

    let test_account = create_basic_wallet(
        init_seed,
        auth,
        AccountType::RegularAccountUpdatableCode,
        AccountStorageMode::Public,
    )?;

    let account_id = test_account.id();

    // Save to file
    let account_file_path = config_dir.join("test_account.mac");
    let account_file = AccountFile::new(test_account, vec![]);
    account_file.write(&account_file_path)?;

    // Create a genesis config TOML that references the account file
    let toml_content = format!(
        r#"
timestamp = 1717344256
version   = 1

[native_faucet]
decimals   = 6
max_supply = 100_000_000
symbol     = "TEST"

[fee_parameters]
verification_base_fee = 0

[[account]]
path = "test_account.mac"
"#
    );

    // Parse the config
    let gcfg = GenesisConfig::read_toml(&toml_content, config_dir)?;

    // Convert to state and verify the account is included
    let (state, _secrets) = gcfg.into_state(SecretKey::new())?;
    assert!(state.accounts.iter().find(|a| a.id() == account_id).is_some());

    Ok(())
}

#[test]
fn parsing_native_faucet_from_file() -> TestResult {
    use miden_protocol::account::{AccountBuilder, AccountFile, AccountStorageMode, AccountType};
    use miden_standards::account::auth::AuthFalcon512Rpo;
    use tempfile::tempdir;

    // Create a temporary directory for our test files
    let temp_dir = tempdir()?;
    let config_dir = temp_dir.path();

    // Create a faucet account and save it to a .mac file
    let init_seed: [u8; 32] = rand::random();
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(rand::random());
    let secret_key = miden_protocol::crypto::dsa::falcon512_rpo::SecretKey::with_rng(
        &mut miden_node_utils::crypto::get_rpo_random_coin(&mut rng),
    );
    let auth = AuthFalcon512Rpo::new(secret_key.public_key().into());

    let faucet_component =
        BasicFungibleFaucet::new(TokenSymbol::new("NFAU").unwrap(), 6, Felt::new(1_000_000_000))?;

    let faucet_account = AccountBuilder::new(init_seed)
        .account_type(AccountType::FungibleFaucet)
        .storage_mode(AccountStorageMode::Public)
        .with_auth_component(auth)
        .with_component(faucet_component)
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

[native_faucet]
path = "native_faucet.mac"

[fee_parameters]
verification_base_fee = 0
"#;

    // Parse the config
    let gcfg = GenesisConfig::read_toml(toml_content, config_dir)?;

    // Convert to state and verify the native faucet is included
    let (state, secrets) = gcfg.into_state(SecretKey::new())?;
    assert!(state.accounts.iter().find(|a| a.id() == faucet_id).is_some());

    // No secrets should be generated for file-loaded native faucet
    assert!(secrets.secrets.is_empty());

    Ok(())
}

#[test]
fn native_faucet_from_file_must_be_faucet_type() -> TestResult {
    use miden_protocol::account::{AccountFile, AccountStorageMode, AccountType};
    use miden_standards::AuthScheme;
    use miden_standards::account::wallets::create_basic_wallet;
    use tempfile::tempdir;

    // Create a temporary directory for our test files
    let temp_dir = tempdir()?;
    let config_dir = temp_dir.path();

    // Create a regular wallet account (not a faucet) and try to use it as native faucet
    let init_seed: [u8; 32] = rand::random();
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(rand::random());
    let secret_key = miden_protocol::crypto::dsa::falcon512_rpo::SecretKey::with_rng(
        &mut miden_node_utils::crypto::get_rpo_random_coin(&mut rng),
    );
    let auth = AuthScheme::Falcon512Rpo { pub_key: secret_key.public_key().into() };

    let regular_account = create_basic_wallet(
        init_seed,
        auth,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Public,
    )?;

    // Save to file
    let account_file_path = config_dir.join("not_a_faucet.mac");
    let account_file = AccountFile::new(regular_account, vec![]);
    account_file.write(&account_file_path)?;

    // Create a genesis config TOML that tries to use a non-faucet as native faucet
    let toml_content = r#"
timestamp = 1717344256
version   = 1

[native_faucet]
path = "not_a_faucet.mac"

[fee_parameters]
verification_base_fee = 0
"#;

    // Parse should fail with NativeFaucetNotFungible error
    let result = GenesisConfig::read_toml(toml_content, config_dir);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, GenesisConfigError::NativeFaucetNotFungible { .. }),
        "Expected NativeFaucetNotFungible error, got: {:?}",
        err
    );

    Ok(())
}

#[test]
fn missing_account_file_returns_error() {
    // Create a genesis config TOML that references a non-existent file
    let toml_content = r#"
timestamp = 1717344256
version   = 1

[native_faucet]
decimals   = 6
max_supply = 100_000_000
symbol     = "TEST"

[fee_parameters]
verification_base_fee = 0

[[account]]
path = "does_not_exist.mac"
"#;

    // Use temp dir as config dir
    let temp_dir = tempfile::tempdir().unwrap();
    let result = GenesisConfig::read_toml(toml_content, temp_dir.path());
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, GenesisConfigError::AccountFileRead { .. }),
        "Expected AccountFileRead error, got: {:?}",
        err
    );
}

#[test]
fn missing_native_faucet_not_allowed() -> TestResult {
    let toml_content = r#"
timestamp = 1717344256
version   = 1

[fee_parameters]
verification_base_fee = 0
"#;

    let result = GenesisConfig::read_toml(toml_content, Path::new("."));
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_matches!(err, GenesisConfigError::Toml(toml_err) => {
        let msg = toml_err.message();
        assert!(
            msg.contains("missing field `native_faucet`"),
            "Expected error message to mention 'native_faucet', got: {msg}"
        );
    });
    Ok(())
}
