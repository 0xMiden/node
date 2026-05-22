use std::io::Write;
use std::path::Path;

use assert_matches::assert_matches;
use miden_protocol::ONE;
use miden_protocol::account::delta::AccountUpdateDetails;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey;

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Helper to write TOML content to a file and return the path
fn write_toml_file(dir: &Path, content: &str) -> std::path::PathBuf {
    let path = dir.join("genesis.toml");
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(content.as_bytes()).unwrap();
    path
}

#[test]
#[miden_node_test_macro::enable_logging]
fn parsing_yields_expected_default_values() -> TestResult {
    // Copy sample file to temp dir since read_toml_file needs a real file path
    let temp_dir = tempfile::tempdir()?;
    let sample_content = include_str!("./samples/01-simple.toml");
    let config_path = write_toml_file(temp_dir.path(), sample_content);

    let gcfg = GenesisConfig::read_toml_file(&config_path)?;
    let signer = SigningKey::new();
    let (state, _secrets) = gcfg.into_state(signer.public_key())?;
    let _ = state;
    // faucets always precede wallet accounts
    let native_faucet = state.accounts[0].clone();
    let _excess = state.accounts[1].clone();
    let wallet1 = state.accounts[2].clone();
    let wallet2 = state.accounts[3].clone();

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
    let faucet_vault_key = miden_protocol::asset::AssetVaultKey::new_fungible(
        native_faucet.id(),
        miden_protocol::asset::AssetCallbackFlag::Disabled,
    );
    assert_matches!(wallet1.vault().get_balance(faucet_vault_key), Ok(val) => {
        assert_eq!(val.as_u64(), 999_000);
    });
    assert_matches!(wallet2.vault().get_balance(faucet_vault_key), Ok(val) => {
        assert_eq!(val.as_u64(), 777);
    });

    // check total issuance of the faucet
    let faucet = FungibleFaucet::try_from(native_faucet.storage()).unwrap();
    assert_eq!(faucet.token_supply().as_u64(), 999_777, "Issuance mismatch");

    Ok(())
}

#[tokio::test]
#[miden_node_test_macro::enable_logging]
async fn genesis_accounts_have_nonce_one() -> TestResult {
    let gcfg = GenesisConfig::default();
    let signer = SigningKey::new();
    let (state, secrets) = gcfg.into_state(signer.public_key()).unwrap();
    let mut iter = secrets.as_account_files(&state);
    let AccountFileWithName { account_file: status_quo, .. } = iter.next().unwrap().unwrap();
    assert!(iter.next().is_none());

    assert_eq!(status_quo.account.nonce(), ONE);

    let _block = state.into_block(&signer)?;
    Ok(())
}

#[test]
fn parsing_account_from_file() -> TestResult {
    use miden_protocol::account::auth::AuthScheme;
    use miden_protocol::account::{AccountFile, AccountType};
    use miden_standards::AuthMethod;
    use miden_standards::account::wallets::create_basic_wallet;
    use tempfile::tempdir;

    // Create a temporary directory for our test files
    let temp_dir = tempdir()?;
    let config_dir = temp_dir.path();

    // Create a test wallet account and save it to a .mac file
    let init_seed: [u8; 32] = rand::random();
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(rand::random());
    let secret_key = miden_protocol::crypto::dsa::falcon512_poseidon2::SecretKey::with_rng(
        &mut miden_node_utils::crypto::get_rpo_random_coin(&mut rng),
    );
    let auth = AuthMethod::SingleSig {
        approver: (secret_key.public_key().into(), AuthScheme::Falcon512Poseidon2),
    };

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
    let signer = SigningKey::new();
    let (state, _secrets) = gcfg.into_state(signer.public_key())?;
    assert!(state.accounts.iter().any(|a| a.id() == account_id));

    Ok(())
}

#[test]
fn parsing_native_faucet_from_file() -> TestResult {
    use miden_protocol::account::auth::AuthScheme;
    use miden_protocol::account::{AccountBuilder, AccountFile, AccountType};
    use miden_protocol::asset::AssetAmount;
    use miden_standards::account::auth::AuthSingleSig;
    use miden_standards::account::policies::{
        BurnPolicyConfig,
        MintPolicyConfig,
        PolicyRegistration,
        TokenPolicyManager,
    };
    use tempfile::tempdir;

    // Create a temporary directory for our test files
    let temp_dir = tempdir()?;
    let config_dir = temp_dir.path();

    // Create a faucet account and save it to a .mac file
    let init_seed: [u8; 32] = rand::random();
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(rand::random());
    let secret_key = miden_protocol::crypto::dsa::falcon512_poseidon2::SecretKey::with_rng(
        &mut miden_node_utils::crypto::get_rpo_random_coin(&mut rng),
    );
    let auth = AuthSingleSig::new(secret_key.public_key().into(), AuthScheme::Falcon512Poseidon2);

    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("MIDEN").unwrap())
        .symbol(TokenSymbol::new("MIDEN").unwrap())
        .decimals(6)
        .max_supply(AssetAmount::new(1_000_000_000)?)
        .build()?;

    let faucet_account = AccountBuilder::new(init_seed)
        .account_type(AccountType::Public)
        .with_auth_component(auth)
        .with_component(faucet)
        .with_components(
            TokenPolicyManager::new()
                .with_mint_policy(MintPolicyConfig::AllowAll, PolicyRegistration::Active)?
                .with_burn_policy(BurnPolicyConfig::AllowAll, PolicyRegistration::Active)?,
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
    let signer = SigningKey::new();
    let (state, secrets) = gcfg.into_state(signer.public_key())?;
    assert!(state.accounts.iter().any(|a| a.id() == faucet_id));

    // No secrets should be generated for file-loaded native faucet
    assert!(secrets.secrets.is_empty());

    Ok(())
}

#[test]
fn native_faucet_from_file_must_be_faucet_type() -> TestResult {
    use miden_protocol::account::auth::AuthScheme;
    use miden_protocol::account::{AccountFile, AccountType};
    use miden_standards::AuthMethod;
    use miden_standards::account::wallets::create_basic_wallet;
    use tempfile::tempdir;

    // Create a temporary directory for our test files
    let temp_dir = tempdir()?;
    let config_dir = temp_dir.path();

    // Create a regular wallet account (not a faucet) and try to use it as native faucet
    let init_seed: [u8; 32] = rand::random();
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(rand::random());
    let secret_key = miden_protocol::crypto::dsa::falcon512_poseidon2::SecretKey::with_rng(
        &mut miden_node_utils::crypto::get_rpo_random_coin(&mut rng),
    );
    let auth = AuthMethod::SingleSig {
        approver: (secret_key.public_key().into(), AuthScheme::Falcon512Poseidon2),
    };

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
    let result = gcfg.into_state(SigningKey::new().public_key());
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
    let result = gcfg.into_state(SigningKey::new().public_key());
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, GenesisConfigError::AccountFileRead(..)),
        "Expected AccountFileRead error, got: {err:?}"
    );
}

#[tokio::test]
#[miden_node_test_macro::enable_logging]
async fn parsing_agglayer_sample_with_account_files() -> TestResult {
    // Use the actual sample file path since it references relative .mac files
    let sample_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/genesis/config/samples/02-with-account-files.toml");

    let gcfg = GenesisConfig::read_toml_file(&sample_path)?;
    let signer = SigningKey::new();
    let (state, secrets) = gcfg.into_state(signer.public_key())?;

    // Should have 4 accounts:
    // 1. Native faucet (MIDEN) - built from parameters
    // 2. Bridge account (bridge.mac) - loaded from file
    // 3. ETH faucet (agglayer_faucet_eth.mac) - loaded from file
    // 4. USDC faucet (agglayer_faucet_usdc.mac) - loaded from file
    assert_eq!(state.accounts.len(), 4, "Expected 4 accounts in genesis state");

    // Verify account types
    let native_faucet = &state.accounts[0];
    let bridge_account = &state.accounts[1];
    let eth_faucet = &state.accounts[2];
    let usdc_faucet = &state.accounts[3];

    // Native faucet should be a fungible faucet (built from parameters)
    let native_faucet_handle =
        FungibleFaucet::try_from(native_faucet).expect("Native faucet should be a FungibleFaucet");
    assert_eq!(*native_faucet_handle.symbol(), TokenSymbol::new("MIDEN").unwrap());

    // Bridge account is not a fungible faucet
    assert!(
        FungibleFaucet::try_from(bridge_account).is_err(),
        "Bridge account should not be a fungible faucet"
    );

    // ETH faucet should be an AggLayer faucet loaded from file
    assert!(
        miden_agglayer::AggLayerFaucet::try_faucet_from_account(eth_faucet).is_ok(),
        "ETH faucet should be an AggLayer faucet"
    );

    // USDC faucet should be an AggLayer faucet loaded from file
    assert!(
        miden_agglayer::AggLayerFaucet::try_faucet_from_account(usdc_faucet).is_ok(),
        "USDC faucet should be an AggLayer faucet"
    );

    // Only the native faucet generates a secret (built from parameters)
    assert_eq!(secrets.secrets.len(), 1, "Only native faucet should generate a secret");

    // Verify the genesis state can be converted to a block
    let block = state.into_block(&signer)?;

    // Verify that non-private (Public) accounts get full Delta details.
    for update in block.inner().body().updated_accounts() {
        let is_private = update.account_id().is_private();
        match update.details() {
            AccountUpdateDetails::Delta(_) => {
                assert!(
                    !is_private,
                    "Private account {:?} should not have Delta details",
                    update.account_id()
                );
            },
            AccountUpdateDetails::Private => {
                assert!(
                    is_private,
                    "Non-private account {:?} should have Delta details, not Private",
                    update.account_id()
                );
            },
        }
    }

    Ok(())
}
