//! Describe a subset of the genesis manifest in easily human readable format

use std::cmp::Ordering;
use std::str::FromStr;

use indexmap::IndexMap;
use miden_node_utils::crypto::get_rpo_random_coin;
use miden_protocol::account::auth::AuthSecretKey;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountDelta,
    AccountFile,
    AccountId,
    AccountStorage,
    AccountStorageDelta,
    AccountStorageMode,
    AccountType,
    AccountVaultDelta,
    FungibleAssetDelta,
    NonFungibleAssetDelta,
};
use miden_protocol::asset::{FungibleAsset, TokenSymbol};
use miden_protocol::block::FeeParameters;
use miden_protocol::crypto::dsa::falcon512_rpo::SecretKey as RpoSecretKey;
use miden_protocol::errors::TokenSymbolError;
use miden_protocol::{Felt, FieldElement, ONE, ZERO};
use miden_standards::AuthScheme;
use miden_standards::account::auth::AuthFalcon512Rpo;
use miden_standards::account::faucets::BasicFungibleFaucet;
use miden_standards::account::wallets::create_basic_wallet;
use rand::distr::weighted::Weight;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};

use crate::GenesisState;

mod errors;
use self::errors::GenesisConfigError;

#[cfg(test)]
mod tests;

// GENESIS CONFIG
// ================================================================================================

/// Specify a set of faucets and wallets with assets for easier test deployments.
///
/// Notice: Any faucet must be declared _before_ it's use in a wallet/regular account.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GenesisConfig {
    version: u32,
    timestamp: u32,
    native_faucet: NativeFaucet,
    fee_parameters: FeeParameterConfig,
    #[serde(default)]
    wallet: Vec<WalletConfig>,
    #[serde(default)]
    fungible_faucet: Vec<FungibleFaucetConfig>,
}

impl Default for GenesisConfig {
    fn default() -> Self {
        let miden = TokenSymbolStr::from_str("MIDEN").unwrap();
        Self {
            version: 1_u32,
            timestamp: u32::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("Time does not go backwards")
                    .as_secs(),
            )
            .expect("Timestamp should fit into u32"),
            wallet: vec![],
            native_faucet: NativeFaucet {
                max_supply: 100_000_000_000_000_000u64,
                decimals: 6u8,
                symbol: miden.clone(),
            },
            fee_parameters: FeeParameterConfig { verification_base_fee: 0 },
            fungible_faucet: vec![],
        }
    }
}

impl GenesisConfig {
    /// Read the genesis accounts from a toml formatted string
    ///
    /// Notice: It will generate the specified case during [`fn into_state`].
    pub fn read_toml(toml_str: &str) -> Result<Self, GenesisConfigError> {
        let me = toml::from_str::<Self>(toml_str)?;
        Ok(me)
    }

    /// Convert the in memory representation into the new genesis state
    ///
    /// Also returns the set of secrets for the generated accounts.
    #[allow(clippy::too_many_lines)]
    pub fn into_state<S>(
        self,
        signer: S,
    ) -> Result<(GenesisState<S>, AccountSecrets), GenesisConfigError> {
        let GenesisConfig {
            version,
            timestamp,
            native_faucet,
            fee_parameters,
            fungible_faucet: fungible_faucet_configs,
            wallet: wallet_configs,
            ..
        } = self;

        let symbol = native_faucet.symbol.clone();

        let mut wallet_accounts = Vec::<Account>::new();
        // Every asset sitting in a wallet, has to reference a faucet for that asset
        let mut faucet_accounts = IndexMap::<TokenSymbolStr, Account>::new();

        // Collect the generated secret keys for the test, so one can interact with those
        // accounts/sign transactions
        let mut secrets = Vec::new();

        // First setup all the faucets
        for fungible_faucet_config in std::iter::once(native_faucet.to_faucet_config())
            .chain(fungible_faucet_configs.into_iter())
        {
            let symbol = fungible_faucet_config.symbol.clone();
            let (faucet_account, secret_key) = fungible_faucet_config.build_account()?;

            if faucet_accounts.insert(symbol.clone(), faucet_account.clone()).is_some() {
                return Err(GenesisConfigError::DuplicateFaucetDefinition { symbol });
            }

            secrets.push((
                format!("faucet_{symbol}.mac", symbol = symbol.to_string().to_lowercase()),
                faucet_account.id(),
                secret_key,
            ));
            // Do _not_ collect the account, only after we know all wallet assets
            // we know the remaining supply in the faucets.
        }

        let native_faucet_account_id = faucet_accounts
            .get(&symbol)
            .expect("Parsing guarantees the existence of a native faucet.")
            .id();

        let fee_parameters =
            FeeParameters::new(native_faucet_account_id, fee_parameters.verification_base_fee)?;

        // Track all adjustments, one per faucet account id
        let mut faucet_issuance = IndexMap::<AccountId, u64>::new();

        let zero_padding_width = usize::ilog10(std::cmp::max(10, wallet_configs.len())) as usize;

        // Setup all wallet accounts, which reference the faucet's for their provided assets.
        for (index, WalletConfig { has_updatable_code, storage_mode, assets }) in
            wallet_configs.into_iter().enumerate()
        {
            tracing::debug!("Adding wallet account {index} with {assets:?}");

            let mut rng = ChaCha20Rng::from_seed(rand::random());
            let secret_key = RpoSecretKey::with_rng(&mut get_rpo_random_coin(&mut rng));
            let auth = AuthScheme::Falcon512Rpo { pub_key: secret_key.public_key().into() };
            let init_seed: [u8; 32] = rng.random();

            let account_type = if has_updatable_code {
                AccountType::RegularAccountUpdatableCode
            } else {
                AccountType::RegularAccountImmutableCode
            };
            let account_storage_mode = storage_mode.into();
            let mut wallet_account =
                create_basic_wallet(init_seed, auth, account_type, account_storage_mode)?;

            // Add fungible assets and track the faucet adjustments per faucet/asset.
            let wallet_fungible_asset_update =
                prepare_fungible_asset_update(assets, &faucet_accounts, &mut faucet_issuance)?;

            // Force the account nonce to 1.
            //
            // By convention, a nonce of zero indicates a freshly generated local account that has
            // yet to be deployed. An account is deployed onchain along with its first
            // transaction which results in a non-zero nonce onchain.
            //
            // The genesis block is special in that accounts are "deployed" without transactions and
            // therefore we need bump the nonce manually to uphold this invariant.
            let wallet_delta = AccountDelta::new(
                wallet_account.id(),
                AccountStorageDelta::default(),
                AccountVaultDelta::new(
                    wallet_fungible_asset_update,
                    NonFungibleAssetDelta::default(),
                ),
                ONE,
            )?;

            wallet_account.apply_delta(&wallet_delta)?;

            debug_assert_eq!(wallet_account.nonce(), ONE);

            secrets.push((
                format!("wallet_{index:0zero_padding_width$}.mac"),
                wallet_account.id(),
                secret_key,
            ));

            wallet_accounts.push(wallet_account);
        }

        let mut all_accounts = Vec::<Account>::new();
        // Apply all fungible faucet adjustments to the respective faucet
        for (symbol, mut faucet_account) in faucet_accounts {
            let faucet_id = faucet_account.id();
            // If there is no account using the asset, we use an empty delta to set the
            // nonce to `ONE`.
            let total_issuance = faucet_issuance.get(&faucet_id).copied().unwrap_or_default();

            let mut storage_delta = AccountStorageDelta::default();

            if total_issuance != 0 {
                // slot 0
                storage_delta.set_item(
                    AccountStorage::faucet_sysdata_slot().clone(),
                    [ZERO, ZERO, ZERO, Felt::new(total_issuance)].into(),
                )?;
                tracing::debug!(
                    "Reducing faucet account {faucet} for {symbol} by {amount}",
                    faucet = faucet_id.to_hex(),
                    symbol = symbol,
                    amount = total_issuance
                );
            } else {
                tracing::debug!(
                    "No wallet is referencing {faucet} for {symbol}",
                    faucet = faucet_id.to_hex(),
                    symbol = symbol,
                );
            }

            faucet_account.apply_delta(&AccountDelta::new(
                faucet_id,
                storage_delta,
                AccountVaultDelta::default(),
                ONE,
            )?)?;

            debug_assert_eq!(faucet_account.nonce(), ONE);

            // sanity check the total issuance against
            let basic = BasicFungibleFaucet::try_from(&faucet_account)?;
            let max_supply = basic.max_supply().inner();
            if max_supply < total_issuance {
                return Err(GenesisConfigError::MaxIssuanceExceeded {
                    max_supply,
                    symbol,
                    total_issuance,
                });
            }

            all_accounts.push(faucet_account);
        }
        // Ensure the faucets always precede the wallets referencing them
        all_accounts.extend(wallet_accounts);

        Ok((
            GenesisState {
                fee_parameters,
                accounts: all_accounts,
                version,
                timestamp,
                block_signer: signer,
            },
            AccountSecrets { secrets },
        ))
    }
}

// NATIVE FAUCET
// ================================================================================================

/// Declare the native fungible asset
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeFaucet {
    /// Token symbol to use for fees.
    symbol: TokenSymbolStr,

    decimals: u8,
    /// Max supply in full token units
    ///
    /// It will be converted internally to the smallest representable unit,
    /// using based `10.powi(decimals)` as a multiplier.
    max_supply: u64,
}

impl NativeFaucet {
    fn to_faucet_config(&self) -> FungibleFaucetConfig {
        let NativeFaucet { symbol, decimals, max_supply, .. } = self;
        FungibleFaucetConfig {
            symbol: symbol.clone(),
            decimals: *decimals,
            max_supply: *max_supply,
            storage_mode: StorageMode::Public,
        }
    }
}

// FEE PARAMETER CONFIG
// ================================================================================================

/// Represents a the fee parameters using the given asset
///
/// A faucet providing the `symbol` token moste exist.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeeParameterConfig {
    /// Verification base fee, in units of smallest denomination.
    verification_base_fee: u32,
}

// FUNGIBLE FAUCET CONFIG
// ================================================================================================

/// Represents a faucet with asset specific properties
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FungibleFaucetConfig {
    symbol: TokenSymbolStr,
    decimals: u8,
    /// Max supply in full token units
    ///
    /// It will be converted internally to the smallest representable unit,
    /// using based `10.powi(decimals)` as a multiplier.
    max_supply: u64,
    #[serde(default)]
    storage_mode: StorageMode,
}

impl FungibleFaucetConfig {
    /// Create a fungible faucet from a config entry
    fn build_account(self) -> Result<(Account, RpoSecretKey), GenesisConfigError> {
        let FungibleFaucetConfig {
            symbol,
            decimals,
            max_supply,
            storage_mode,
        } = self;
        let mut rng = ChaCha20Rng::from_seed(rand::random());
        let secret_key = RpoSecretKey::with_rng(&mut get_rpo_random_coin(&mut rng));
        let auth = AuthFalcon512Rpo::new(secret_key.public_key().into());
        let init_seed: [u8; 32] = rng.random();

        let max_supply = Felt::try_from(max_supply)
            .expect("The `Felt::MODULUS` is _always_ larger than the `max_supply`");

        let component = BasicFungibleFaucet::new(*symbol.as_ref(), decimals, max_supply)?;

        // It's similar to `fn create_basic_fungible_faucet`, but we need to cover more cases.
        let faucet_account = AccountBuilder::new(init_seed)
            .account_type(AccountType::FungibleFaucet)
            .storage_mode(storage_mode.into())
            .with_auth_component(auth)
            .with_component(component)
            .build()?;

        debug_assert_eq!(faucet_account.nonce(), Felt::ZERO);

        Ok((faucet_account, secret_key))
    }
}

// WALLET CONFIG
// ================================================================================================

/// Represents a wallet, containing a set of assets
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletConfig {
    #[serde(default)]
    has_updatable_code: bool,
    #[serde(default)]
    storage_mode: StorageMode,
    assets: Vec<AssetEntry>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct AssetEntry {
    symbol: TokenSymbolStr,
    /// The amount of full token units the given asset is populated with
    amount: u64,
}

// STORAGE MODE
// ================================================================================================

/// See the [full description](https://0xmiden.github.io/miden-base/account.html?highlight=Accoun#account-storage-mode)
/// for details
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, Default)]
pub enum StorageMode {
    /// Monitor for `Notes` related to the account, in addition to being `Public`.
    #[serde(alias = "network")]
    #[default]
    Network,
    /// A publicly stored account, lives on-chain.
    #[serde(alias = "public")]
    Public,
    /// A private account, which must be known by interactors.
    #[serde(alias = "private")]
    Private,
}

impl From<StorageMode> for AccountStorageMode {
    fn from(mode: StorageMode) -> AccountStorageMode {
        match mode {
            StorageMode::Network => AccountStorageMode::Network,
            StorageMode::Private => AccountStorageMode::Private,
            StorageMode::Public => AccountStorageMode::Public,
        }
    }
}

// ACCOUNTS
// ================================================================================================

#[derive(Debug, Clone)]
pub struct AccountFileWithName {
    pub name: String,
    pub account_file: AccountFile,
}

/// Secrets generated during the state generation
#[derive(Debug, Clone)]
pub struct AccountSecrets {
    // name, account, private key, account seed
    pub secrets: Vec<(String, AccountId, RpoSecretKey)>,
}

impl AccountSecrets {
    /// Convert the internal tuple into an `AccountFile`
    ///
    /// If no name is present, a new one is generated based on the current time
    /// and the index in
    pub fn as_account_files<S>(
        &self,
        genesis_state: &GenesisState<S>,
    ) -> impl Iterator<Item = Result<AccountFileWithName, GenesisConfigError>> + use<'_, S> {
        let account_lut = IndexMap::<AccountId, Account>::from_iter(
            genesis_state.accounts.iter().map(|account| (account.id(), account.clone())),
        );
        self.secrets.iter().cloned().map(move |(name, account_id, secret_key)| {
            let account = account_lut
                .get(&account_id)
                .ok_or(GenesisConfigError::MissingGenesisAccount { account_id })?;
            let account_file =
                AccountFile::new(account.clone(), vec![AuthSecretKey::Falcon512Rpo(secret_key)]);
            Ok(AccountFileWithName { name, account_file })
        })
    }
}

// HELPERS
// ================================================================================================

/// Process wallet assets and return them as a fungible asset delta.
/// Track the negative adjustments for the respective faucets.
fn prepare_fungible_asset_update(
    assets: impl IntoIterator<Item = AssetEntry>,
    faucets: &IndexMap<TokenSymbolStr, Account>,
    faucet_issuance: &mut IndexMap<AccountId, u64>,
) -> Result<FungibleAssetDelta, GenesisConfigError> {
    let assets =
        Result::<Vec<_>, _>::from_iter(assets.into_iter().map(|AssetEntry { amount, symbol }| {
            let faucet_account = faucets.get(&symbol).ok_or_else(|| {
                GenesisConfigError::MissingFaucetDefinition { symbol: symbol.clone() }
            })?;

            Ok::<_, GenesisConfigError>(FungibleAsset::new(faucet_account.id(), amount)?)
        }))?;

    let mut wallet_asset_delta = FungibleAssetDelta::default();
    assets
        .into_iter()
        .try_for_each(|fungible_asset| wallet_asset_delta.add(fungible_asset))?;

    wallet_asset_delta.iter().try_for_each(|(faucet_id, amount)| {
        let issuance: &mut u64 = faucet_issuance.entry(*faucet_id).or_default();
        tracing::debug!(
            "Updating faucet issuance {faucet} with {issuance} += {amount}",
            faucet = faucet_id.to_hex()
        );

        // check against total supply is deferred
        issuance
            .checked_add_assign(
                &u64::try_from(*amount)
                    .expect("Issuance must always be positive in the scope of genesis config"),
            )
            .map_err(|_| GenesisConfigError::IssuanceOverflow)?;

        Ok::<_, GenesisConfigError>(())
    })?;

    Ok(wallet_asset_delta)
}

/// Wrapper type used for configuration representation.
///
/// Required since `Felt` does not implement `Hash` or `Eq`, but both are useful and necessary for a
/// coherent model construction.
#[derive(Debug, Clone, PartialEq)]
pub struct TokenSymbolStr {
    /// The raw representation, used for `Hash` and `Eq`.
    raw: String,
    /// Maintain the duality with the actual implementation.
    encoded: TokenSymbol,
}

impl AsRef<TokenSymbol> for TokenSymbolStr {
    fn as_ref(&self) -> &TokenSymbol {
        &self.encoded
    }
}

impl std::fmt::Display for TokenSymbolStr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.raw)
    }
}

impl FromStr for TokenSymbolStr {
    // note: we re-use the error type
    type Err = TokenSymbolError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self {
            encoded: TokenSymbol::new(s)?,
            raw: s.to_string(),
        })
    }
}

impl Eq for TokenSymbolStr {}

impl From<TokenSymbolStr> for TokenSymbol {
    fn from(value: TokenSymbolStr) -> Self {
        value.encoded
    }
}

impl Ord for TokenSymbolStr {
    fn cmp(&self, other: &Self) -> Ordering {
        self.raw.cmp(&other.raw)
    }
}

impl PartialOrd for TokenSymbolStr {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl std::hash::Hash for TokenSymbolStr {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.raw.hash::<H>(state);
    }
}

impl Serialize for TokenSymbolStr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.raw)
    }
}

impl<'de> Deserialize<'de> for TokenSymbolStr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(TokenSymbolVisitor)
    }
}

use serde::de::Visitor;

struct TokenSymbolVisitor;

impl Visitor<'_> for TokenSymbolVisitor {
    type Value = TokenSymbolStr;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("1 to 6 uppercase ascii letters")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let encoded = TokenSymbol::new(v).map_err(|e| E::custom(format!("{e}")))?;
        let raw = v.to_string();
        Ok(TokenSymbolStr { raw, encoded })
    }
}
