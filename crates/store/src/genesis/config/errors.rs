use miden_protocol::account::AccountId;
use miden_protocol::errors::{
    AccountDeltaError,
    AccountError,
    AssetError,
    FeeError,
    TokenSymbolError,
};
use miden_protocol::utils::DeserializationError;
use miden_standards::account::faucets::FungibleFaucetError;
use miden_standards::account::wallets::BasicWalletError;

use crate::genesis::config::TokenSymbolStr;

#[allow(missing_docs, reason = "Error variants must be descriptive by themselves")]
#[derive(Debug, thiserror::Error)]
pub enum GenesisConfigError {
    #[error(transparent)]
    Toml(#[from] toml::de::Error),
    #[error("account translation from config to state failed")]
    Account(#[from] AccountError),
    #[error("asset translation from config to state failed")]
    Asset(#[from] AssetError),
    #[error("adding assets to account failed")]
    AccountDelta(#[from] AccountDeltaError),
    #[error("the defined asset {symbol:?} has no corresponding faucet")]
    MissingFaucetDefinition { symbol: TokenSymbolStr },
    #[error("account with id {account_id} was referenced but is not part of given genesis state")]
    MissingGenesisAccount { account_id: AccountId },
    #[error(transparent)]
    TokenSymbol(#[from] TokenSymbolError),
    #[error("unsupported value for key {key} : {value}")]
    UnsupportedValue {
        key: &'static str,
        value: String,
        message: String,
    },
    #[error("failed to create fungible faucet account")]
    FungibleFaucet(#[from] FungibleFaucetError),
    #[error("failed to create basic wallet account")]
    BasicWallet(#[from] BasicWalletError),
    #[error(r#"incompatible combination of `max_supply` ({max_supply})" and `decimals` ({decimals}) exceeding the allowed value range of an `u64`"#)]
    OutOfRange { max_supply: u64, decimals: u8 },
    #[error("Found duplicate faucet definition for token symbol {symbol:?}")]
    DuplicateFaucetDefinition { symbol: TokenSymbolStr },
    #[error(
        "Total issuance {total_issuance} of {symbol:?} exceeds faucet's maximum issuance of {max_supply}"
    )]
    MaxIssuanceExceeded {
        symbol: TokenSymbolStr,
        total_issuance: u64,
        max_supply: u64,
    },
    #[error("Total issuance overflowed u64")]
    IssuanceOverflow,
    #[error("missing fee faucet for native asset {0}")]
    MissingFeeFaucet(TokenSymbolStr),
    #[error("fee error")]
    FeeError(#[from] FeeError),
    #[error("faucet account of {0} is not a fungible faucet")]
    NativeAssetFaucetIsNotPublic(TokenSymbolStr),
    #[error("faucet account of {0} is not public")]
    NativeAssetFaucitIsNotAFungibleFaucet(TokenSymbolStr),
    #[error("invalid secret key")]
    InvalidSecretKey(#[from] DeserializationError),
    #[error("provided signer config is not supported")]
    UnsupportedSignerConfig,
}
