//! The accounts this tool builds and amends: the genesis xUSDC faucet and its distributor.

use anyhow::{Context, Result};
use miden_objects::account_file::AccountFile;
use miden_protocol::account::auth::{AuthScheme, AuthSecretKey};
use miden_protocol::account::{
    Account, AccountBuilder, AccountId, AccountIdVersion, AccountType, AssetCallbackFlag,
};
use miden_protocol::asset::{Asset, AssetAmount, AssetId, FungibleAsset};
use miden_protocol::block::FeeParameters;
use miden_protocol::errors::{AccountError, AssetError, AssetVaultError, AuthSchemeError};
use miden_protocol::{Felt, ZERO};
use miden_standards::account::auth::AuthSingleSig;
use miden_standards::account::faucets::{FungibleFaucet, FungibleFaucetError};
use miden_standards::account::wallets::BasicWallet;
use xusdc_encoding::account::xreserve::{
    XReserveStablecoinBuilder, XReserveStablecoinBuilderError,
};
use xusdc_encoding::xreserve::encoding::DepositNonce;

use crate::config::GenesisToolConfig;

// FAUCET
// ================================================================================================

/// The dummy fee faucet id the fee asset names while the faucet's own id is derived.
fn placeholder_fee_faucet_id() -> AccountId {
    AccountId::dummy(
        [0; 15],
        AccountIdVersion::Version1,
        AccountType::Public,
        AssetCallbackFlag::Disabled,
    )
}

/// Builds the genesis faucet from the config, with the supply cap at [`AssetAmount::MAX`].
pub fn build_faucet(config: &GenesisToolConfig) -> Result<Account> {
    let faucet_config = &config.faucet;
    let fee_parameters = FeeParameters::new(faucet_config.verification_base_fee);
    let min_burn_amount = faucet_config
        .min_burn_amount
        .map(AssetAmount::new)
        .transpose()
        .context("min_burn_amount is not a valid asset amount")?;
    XReserveStablecoinBuilder::builder()
        .token_supply(faucet_config.token_supply)
        .owner(config.accounts.owner)
        .attest_admin_holders(config.accounts.attest_admins.clone())
        .pauser_holders(config.accounts.pausers.clone())
        .unpauser_holders(config.accounts.unpausers.clone())
        .blocklist_manager_holders(config.accounts.blocklist_managers.clone())
        .fee_parameters(fee_parameters)
        .fee_asset_id(AssetId::new_fungible(placeholder_fee_faucet_id()))
        .domain(faucet_config.domain)
        .attesters(faucet_config.attesters.clone())
        .maybe_min_burn_amount(min_burn_amount)
        .build()
        .context("composing the xUSDC faucet builder")?
        .build_genesis_account(faucet_config.seed)
        .context("building the genesis faucet account")
}

/// Records `nonces` as consumed in the genesis `faucet` and returns the amended faucet.
pub fn record_nonces(
    faucet: &Account,
    nonces: &[DepositNonce],
) -> Result<Account, XReserveStablecoinBuilderError> {
    xusdc_encoding::record_used_nonces(faucet.clone(), nonces)
}

// DISTRIBUTOR
// ================================================================================================

/// Generates a fresh distributor: a public basic wallet, undeployed (nonce zero, empty vault),
/// controlled by a newly generated `scheme` key. The returned file carries that key.
pub fn new_distributor(scheme: AuthScheme) -> Result<AccountFile, NewDistributorError> {
    let secret_key = AuthSecretKey::with_scheme(scheme).map_err(NewDistributorError::Scheme)?;
    new_distributor_with(rand::random(), secret_key).map_err(NewDistributorError::Account)
}

/// Builds the distributor from `init_seed` and `secret_key`: a public basic wallet whose
/// single-sig auth is `secret_key`'s scheme and public key, undeployed (nonce zero, empty
/// vault). The returned file carries the key.
pub fn new_distributor_with(
    init_seed: [u8; 32],
    secret_key: AuthSecretKey,
) -> Result<AccountFile, AccountError> {
    let account = AccountBuilder::new(init_seed)
        .account_type(AccountType::Public)
        .with_component(AuthSingleSig::from_public_key(secret_key.public_key()))
        .with_component(BasicWallet)
        .build()?;
    Ok(AccountFile::new(account, vec![secret_key]))
}

/// Prefunds the distributor with the faucet's whole recorded token supply and promotes it to
/// genesis form (nonce one, no seed), keeping its keys. The distributor must be a fresh public
/// wallet (nonce zero) carrying a signing key.
pub fn prefund_distributor(
    faucet: &Account,
    distributor: &AccountFile,
) -> Result<AccountFile, PrefundError> {
    let supply = FungibleFaucet::try_from(faucet)
        .map_err(PrefundError::NotAFungibleFaucet)?
        .token_supply();
    if supply == AssetAmount::ZERO {
        return Err(PrefundError::NothingToDistribute);
    }

    let account = distributor.account();
    let id = account.id();
    if !id.is_public() {
        return Err(PrefundError::DistributorNotPublic(id));
    }
    if account.nonce() != ZERO {
        return Err(PrefundError::DistributorNotFresh {
            id,
            nonce: account.nonce(),
        });
    }
    if distributor.auth_secret_keys().is_empty() {
        return Err(PrefundError::DistributorHasNoSigningKey(id));
    }

    let asset = FungibleAsset::new(faucet.id(), supply.as_u64()).map_err(PrefundError::Asset)?;
    let (id, mut vault, storage, code, _nonce, _seed) = account.clone().into_parts();
    vault
        .add_asset(Asset::from(asset))
        .map_err(PrefundError::Vault)?;
    let prefunded =
        Account::new(id, vault, storage, code, Felt::ONE, None).map_err(PrefundError::Account)?;
    Ok(AccountFile::new(
        prefunded,
        distributor.auth_secret_keys().to_vec(),
    ))
}

// ERRORS
// ================================================================================================

/// Errors [`new_distributor`] returns.
#[derive(Debug, thiserror::Error)]
pub enum NewDistributorError {
    /// The requested auth scheme cannot generate a key.
    #[error("generating the distributor's signing key")]
    Scheme(#[source] AuthSchemeError),
    /// The wallet did not compose.
    #[error("composing the distributor wallet")]
    Account(#[source] AccountError),
}

/// Errors [`prefund_distributor`] returns.
#[derive(Debug, thiserror::Error)]
pub enum PrefundError {
    /// The faucet input is not a fungible faucet account.
    #[error("the faucet file is not a fungible faucet")]
    NotAFungibleFaucet(#[source] FungibleFaucetError),
    /// The faucet records no token supply, so there is nothing to distribute.
    #[error("the faucet records no token supply, nothing to distribute")]
    NothingToDistribute,
    /// The distributor is not a public account.
    #[error("the distributor {} is not a public account", .0.to_hex())]
    DistributorNotPublic(AccountId),
    /// The distributor is not undeployed (nonce zero); it may already be prefunded.
    #[error(
        "the distributor {} is not undeployed (nonce {}), prefund runs once per distributor",
        .id.to_hex(),
        .nonce.as_canonical_u64()
    )]
    DistributorNotFresh { id: AccountId, nonce: Felt },
    /// The distributor file carries no signing key.
    #[error("the distributor file for {} carries no signing key", .0.to_hex())]
    DistributorHasNoSigningKey(AccountId),
    /// The supply is not a valid fungible asset of the faucet.
    #[error("the token supply is not a valid asset of the faucet")]
    Asset(#[source] AssetError),
    /// The supply could not be added to the distributor's vault.
    #[error("adding the token supply to the distributor's vault")]
    Vault(#[source] AssetVaultError),
    /// The prefunded distributor did not re-assemble.
    #[error("re-assembling the prefunded distributor")]
    Account(#[source] AccountError),
}
