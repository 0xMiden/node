use std::path::Path;

use assert_matches::assert_matches;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey;
use miden_protocol::utils::serde::Deserializable;

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn inputs() -> GenesisInputs {
    let (mut native_faucet, _) = FungibleFaucetConfig {
        symbol: TokenSymbolStr::from_str("USDCX").unwrap(),
        decimals: 6,
        max_supply: 1_000_000_000,
        account_type: AccountTypeConfig::Public,
    }
    .build_account()
    .unwrap();
    native_faucet.set_nonce(ONE).unwrap();
    let faucet = FungibleFaucet::try_from(&native_faucet)
        .unwrap()
        .with_token_supply(AssetAmount::new(1_000).unwrap())
        .unwrap();
    let slot = faucet.token_config_slot_value();
    native_faucet.storage_mut().set_item(slot.name(), slot.value()).unwrap();
    let secret =
        AuthSecretKey::with_scheme_and_rng(AuthScheme::EcdsaK256Keccak, &mut rand::rng()).unwrap();
    let mut funding_account = create_basic_wallet(
        rand::random(),
        Approver::from(&secret.public_key()),
        AccountType::Public,
    )
    .unwrap();
    funding_account.set_nonce(ONE).unwrap();
    let validator_key = SigningKey::read_from_bytes(&[7; 32]).unwrap().public_key();
    GenesisInputs {
        native_faucet,
        funding_account,
        fee_parameters: FeeParameters::new(7),
        timestamp: 1717344256,
        validator_config: ValidatorConfig::new(vec![validator_key], 1).unwrap(),
    }
}

fn parse(toml: &str) -> GenesisConfig {
    GenesisConfig::read_toml(toml, Path::new(".")).unwrap()
}

#[test]
fn required_inputs_are_preserved_without_additional_accounts() -> TestResult {
    let inputs = inputs();
    let (state, secrets) = GenesisConfig::default().into_state(inputs.clone())?;
    assert_eq!(state.accounts, vec![inputs.native_faucet.clone(), inputs.funding_account]);
    assert_eq!(state.timestamp, inputs.timestamp);
    assert_eq!(state.fee_parameters, inputs.fee_parameters);
    assert_eq!(state.validator_config, inputs.validator_config);
    assert_eq!(state.protocol_config.fee_asset_id().faucet_id(), inputs.native_faucet.id());
    assert!(secrets.as_account_files(&state).next().is_none());
    let block = state.into_block()?;
    assert!(block.inner().signatures().is_empty());
    assert_eq!(block.inner().header().timestamp(), inputs.timestamp);
    assert_eq!(block.inner().header().fee_parameters().verification_base_fee(), 7);
    Ok(())
}

#[test]
fn native_supply_is_independent_of_funding_balance() -> TestResult {
    for balance in [0, 10, 2_000] {
        let mut inputs = inputs();
        let asset_id = AssetId::new_fungible(inputs.native_faucet.id());
        if balance != 0 {
            inputs
                .funding_account
                .vault_mut()
                .add_asset(FungibleAsset::new(inputs.native_faucet.id(), balance)?.into())?;
        }
        let funding_id = inputs.funding_account.id();
        let (state, _) = GenesisConfig::default().into_state(inputs)?;
        let native = &state.accounts[0];
        assert_eq!(FungibleFaucet::try_from(native)?.token_supply().as_u64(), 1_000);
        let funding = state.accounts.iter().find(|a| a.id() == funding_id).unwrap();
        assert_eq!(funding.vault().get_balance(asset_id)?.as_u64(), balance);
        state.into_block()?;
    }
    Ok(())
}

#[test]
fn additional_native_wallets_increase_supply_and_preserve_funding() -> TestResult {
    let mut inputs = inputs();
    inputs
        .funding_account
        .vault_mut()
        .add_asset(FungibleAsset::new(inputs.native_faucet.id(), 2_000)?.into())?;
    let funding = inputs.funding_account.clone();
    let native_id = inputs.native_faucet.id();
    let config = parse(
        r#"
[[wallet]]
name = "alice"
account_type = "public"
assets = [{ amount = 30, symbol = "USDCX" }]

[[wallet]]
name = "bob"
assets = [{ amount = 40, symbol = "USDCX" }]
"#,
    );
    let (state, secrets) = config.into_state(inputs)?;
    assert!(state.accounts.contains(&funding));
    let native = state.accounts.iter().find(|a| a.id() == native_id).unwrap();
    assert_eq!(FungibleFaucet::try_from(native)?.token_supply().as_u64(), 1_070);
    let files = secrets.as_account_files(&state).collect::<Result<Vec<_>, _>>()?;
    for (name, amount) in [("alice.mac", 30), ("bob.mac", 40)] {
        let file = &files.iter().find(|f| f.name == name).unwrap().account_file;
        assert_eq!(file.account().nonce(), ONE);
        assert_eq!(
            file.account().vault().get_balance(AssetId::new_fungible(native_id))?.as_u64(),
            amount
        );
        assert_eq!(file.auth_secret_keys().len(), 1);
    }
    state.into_block()?;
    Ok(())
}

#[test]
fn sample_creates_wallets_and_an_additional_faucet() -> TestResult {
    let config = parse(include_str!("samples/01-simple.toml"));
    let (state, secrets) = config.into_state(inputs())?;
    let files = secrets.as_account_files(&state).collect::<Result<Vec<_>, _>>()?;
    let faucet = files.iter().find(|f| f.name == "faucet_what.mac").unwrap();
    assert_eq!(
        FungibleFaucet::try_from(faucet.account_file.account())?.token_supply().as_u64(),
        1
    );
    let wallet = files.iter().find(|f| f.name == "wallet_what.mac").unwrap();
    assert_eq!(
        wallet
            .account_file
            .account()
            .vault()
            .get_balance(AssetId::new_fungible(faucet.account_file.account().id()))?
            .as_u64(),
        1
    );
    state.into_block()?;
    Ok(())
}

#[test]
fn additional_account_paths_are_relative_to_the_config() -> TestResult {
    let dir = tempfile::tempdir()?;
    let account = inputs().funding_account;
    AccountFile::new(account.clone(), vec![]).write(dir.path().join("extra.mac"))?;
    let config_path = dir.path().join("accounts.toml");
    fs_err::write(&config_path, "[[account]]\npath = 'extra.mac'\n")?;
    let config = GenesisConfig::read_toml_file(&config_path)?;
    let (state, _) = config.into_state(inputs())?;
    assert!(state.accounts.contains(&account));
    Ok(())
}

#[test]
fn account_config_rejects_network_parameters() {
    for toml in [
        "timestamp = 1717344256",
        "native_faucet = 'native.mac'",
        "funding_account = 'funding.mac'",
        "[fee_parameters]\nverification_base_fee = 7",
    ] {
        assert!(GenesisConfig::read_toml(toml, Path::new(".")).is_err());
    }
}

#[test]
fn native_faucet_must_be_fungible() {
    let mut inputs = inputs();
    inputs.native_faucet = inputs.funding_account.clone();
    assert_matches!(
        GenesisConfig::default().into_state(inputs),
        Err(GenesisConfigError::NativeFaucetNotFungible { .. })
    );
}

#[test]
fn funding_account_must_be_public() {
    let mut inputs = inputs();
    let secret =
        AuthSecretKey::with_scheme_and_rng(AuthScheme::EcdsaK256Keccak, &mut rand::rng()).unwrap();
    inputs.funding_account = create_basic_wallet(
        rand::random(),
        Approver::from(&secret.public_key()),
        AccountType::Private,
    )
    .unwrap();
    inputs.funding_account.set_nonce(ONE).unwrap();
    assert_matches!(
        GenesisConfig::default().into_state(inputs),
        Err(GenesisConfigError::FundingAccountNotPublic { .. })
    );
}

#[test]
fn required_accounts_must_be_ready_for_genesis() {
    let mut inputs = inputs();
    let secret =
        AuthSecretKey::with_scheme_and_rng(AuthScheme::EcdsaK256Keccak, &mut rand::rng()).unwrap();
    inputs.funding_account = create_basic_wallet(
        rand::random(),
        Approver::from(&secret.public_key()),
        AccountType::Public,
    )
    .unwrap();
    assert_matches!(
        GenesisConfig::default().into_state(inputs),
        Err(GenesisConfigError::UndeployedAccount { .. })
    );
}

#[test]
fn duplicate_imported_accounts_are_rejected() -> TestResult {
    let inputs = inputs();
    let dir = tempfile::tempdir()?;
    AccountFile::new(inputs.funding_account.clone(), vec![])
        .write(dir.path().join("funding.mac"))?;
    let config = GenesisConfig::read_toml("[[account]]\npath = 'funding.mac'", dir.path())?;
    assert_matches!(config.into_state(inputs), Err(GenesisConfigError::DuplicateAccount { .. }));
    Ok(())
}

#[test]
fn additional_issuance_must_fit_the_faucet_cap() {
    let config = parse(
        r#"
[[wallet]]
name = "too_many"
assets = [{ amount = 1_000_000_000, symbol = "USDCX" }]
"#,
    );
    assert_matches!(
        config.into_state(inputs()),
        Err(GenesisConfigError::MaxIssuanceExceeded { .. })
    );
}

#[test]
fn missing_account_file_returns_error() {
    let config = parse("[[account]]\npath = 'does_not_exist.mac'");
    assert_matches!(config.into_state(inputs()), Err(GenesisConfigError::AccountFileRead(..)));
}

#[test]
fn duplicate_wallet_names_are_rejected() {
    let config = parse(
        r#"
[[wallet]]
name = "duplicate"
assets = []
[[wallet]]
name = "duplicate"
assets = []
"#,
    );
    assert_matches!(
        config.into_state(inputs()),
        Err(GenesisConfigError::DuplicateAccountFileName { .. })
    );
}
