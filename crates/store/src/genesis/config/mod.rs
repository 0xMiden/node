//! Additional accounts for the genesis state.

use std::cmp::Ordering;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use indexmap::IndexMap;
use miden_node_tracing::debug;
use miden_objects::account_file::AccountFile;
use miden_protocol::account::auth::{AuthScheme, AuthSecretKey};
use miden_protocol::account::{Account, AccountBuilder, AccountId, AccountType};
use miden_protocol::asset::{Asset, AssetAmount, AssetId, FungibleAsset, TokenSymbol};
use miden_protocol::block::{FeeParameters, ValidatorConfig};
use miden_protocol::crypto::dsa::falcon512_poseidon2::SecretKey as RpoSecretKey;
use miden_protocol::errors::TokenSymbolError;
use miden_protocol::protocol_config::ProtocolConfig;
use miden_protocol::{Felt, ONE};
use miden_standards::account::auth::{Approver, AuthSingleSig};
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use miden_standards::account::policies::{BurnPolicy, MintPolicy, TokenPolicyManager};
use miden_standards::account::wallets::create_basic_wallet;
use rand::distr::weighted::Weight;
use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};

use crate::{GenesisState, LOG_TARGET};

mod errors;
use self::errors::GenesisConfigError;

#[cfg(test)]
mod tests;

/// Required inputs for the genesis state.
#[derive(Debug, Clone)]
pub struct GenesisInputs {
    pub native_faucet: Account,
    pub funding_account: Account,
    pub fee_parameters: FeeParameters,
    pub timestamp: u32,
    pub validator_config: ValidatorConfig,
}

// GENESIS CONFIG
// ================================================================================================

/// An account loaded from a `.mac` file (path relative to genesis config directory).
///
/// Notice: Generic accounts are not validated (e.g. that their vault assets reference known
/// faucets), leaving the responsibility of ensuring valid genesis state to the operator.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GenericAccountConfig {
    path: PathBuf,
}

/// Additional faucets, wallets, and account files to include in genesis.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisConfig {
    #[serde(default)]
    wallet: Vec<WalletConfig>,
    #[serde(default)]
    fungible_faucet: Vec<FungibleFaucetConfig>,
    #[serde(default)]
    account: Vec<GenericAccountConfig>,
    #[serde(skip)]
    config_dir: PathBuf,
}

impl GenesisConfig {
    /// Read additional accounts from a TOML file.
    ///
    /// The parent directory of `path` is used to resolve relative paths for account files
    /// referenced in the configuration (e.g., `[[account]]` entries with `path` fields).
    pub fn read_toml_file(path: &Path) -> Result<Self, GenesisConfigError> {
        let toml_str = fs_err::read_to_string(path)
            .map_err(|e| GenesisConfigError::ConfigFileRead(e, path.to_path_buf()))?;
        let config_dir = path.parent().expect("config file path must have a parent directory");
        Self::read_toml(&toml_str, config_dir)
    }

    /// Parse additional accounts and resolve file paths relative to `config_dir`.
    fn read_toml(toml_str: &str, config_dir: &Path) -> Result<Self, GenesisConfigError> {
        let mut config: Self = toml::from_str(toml_str)?;
        config.config_dir = config_dir.to_path_buf();
        Ok(config)
    }

    /// Build the genesis state from the required inputs and additional accounts.
    ///
    /// The genesis header commits to the validator set in `inputs`.
    /// That set must sign every block after genesis.
    ///
    /// Also returns the set of secrets for the generated accounts.
    #[expect(clippy::too_many_lines)]
    pub fn into_state(
        self,
        inputs: GenesisInputs,
    ) -> Result<(GenesisState, AccountSecrets), GenesisConfigError> {
        let GenesisInputs {
            native_faucet,
            funding_account,
            fee_parameters,
            timestamp,
            validator_config,
        } = inputs;
        let GenesisConfig {
            fungible_faucet: fungible_faucet_configs,
            wallet: wallet_configs,
            account: account_entries,
            config_dir,
        } = self;

        // Load account files from disk
        let file_loaded_accounts = account_entries
            .into_iter()
            .map(|acc| {
                let full_path = config_dir.join(&acc.path);
                let account_file = AccountFile::read(&full_path)
                    .map_err(|e| GenesisConfigError::AccountFileRead(e, full_path.clone()))?;
                Ok(account_file.into_parts().0)
            })
            .collect::<Result<Vec<_>, GenesisConfigError>>()?;

        let mut wallet_accounts = Vec::<Account>::new();
        // Every asset sitting in a wallet, has to reference a faucet for that asset
        let mut faucet_accounts = IndexMap::<TokenSymbolStr, Account>::new();

        // Keep the generated keys for account file exports.
        let mut secrets = Vec::new();

        let native_faucet_account_id = native_faucet.id();
        let faucet = FungibleFaucet::try_from(&native_faucet).map_err(|_| {
            GenesisConfigError::NativeFaucetNotFungible { account_id: native_faucet_account_id }
        })?;
        if funding_account.id().account_type() != AccountType::Public {
            return Err(GenesisConfigError::FundingAccountNotPublic {
                account_id: funding_account.id(),
            });
        }
        for account in [&native_faucet, &funding_account] {
            if account.nonce() == Felt::ZERO {
                return Err(GenesisConfigError::UndeployedAccount { account_id: account.id() });
            }
        }

        // Additional wallet allocations increase the imported supply. The funding account balance
        // does not determine that supply.
        let mut faucet_issuance = IndexMap::<AccountId, u64>::new();
        faucet_issuance.insert(native_faucet_account_id, faucet.token_supply().as_u64());
        faucet_accounts.insert(TokenSymbolStr::from(faucet.symbol().clone()), native_faucet);

        // Setup additional fungible faucets from parameters
        for fungible_faucet_config in fungible_faucet_configs {
            let symbol = fungible_faucet_config.symbol.clone();
            let (faucet_account, secret_key) = fungible_faucet_config.build_account()?;

            if faucet_accounts.insert(symbol.clone(), faucet_account.clone()).is_some() {
                return Err(GenesisConfigError::DuplicateFaucetDefinition { symbol });
            }

            secrets.push((
                format!("faucet_{symbol}.mac", symbol = symbol.to_string().to_lowercase()),
                faucet_account.id(),
                Some(AuthSecretKey::Falcon512Poseidon2(secret_key)),
            ));
        }

        let protocol_config =
            ProtocolConfig::current(AssetId::new_fungible(native_faucet_account_id))?;

        // Setup all wallet accounts, which reference the faucet's for their provided assets.
        for (index, WalletConfig { name, account_type, auth_scheme, assets }) in
            wallet_configs.into_iter().enumerate()
        {
            debug!(
                target: LOG_TARGET,
                "Adding wallet account",
                account.index = index,
                account.assets.count = assets.len()
            );

            // The name is joined onto the accounts directory, so it must be a plain file name.
            if Path::new(&name).file_name() != Some(name.as_ref()) {
                return Err(GenesisConfigError::InvalidAccountFileName { name });
            }

            let auth_scheme = auth_scheme
                .as_deref()
                .map(AuthScheme::from_str)
                .transpose()?
                .unwrap_or(AuthScheme::Falcon512Poseidon2);

            let mut rng = ChaCha20Rng::from_seed(rand::random());
            let secret_key = AuthSecretKey::with_scheme_and_rng(auth_scheme, &mut rng)?;
            let auth = Approver::from(&secret_key.public_key());
            let init_seed: [u8; 32] = rng.random();

            let mut wallet_account = create_basic_wallet(init_seed, auth, account_type.into())?;

            // Add fungible assets and track the faucet adjustments per faucet/asset.
            let wallet_assets =
                prepare_fungible_asset_update(assets, &faucet_accounts, &mut faucet_issuance)?;
            for asset in wallet_assets {
                wallet_account.vault_mut().add_asset(asset)?;
            }

            // Force the account nonce to 1.
            //
            // By convention, a nonce of zero indicates a freshly generated local account that has
            // yet to be deployed. An account is deployed onchain along with its first
            // transaction which results in a non-zero nonce onchain.
            //
            // The genesis block is special in that accounts are "deployed" without transactions and
            // therefore we need bump the nonce manually to uphold this invariant.
            wallet_account.set_nonce(ONE)?;

            debug_assert_eq!(wallet_account.nonce(), ONE);

            secrets.push((format!("{name}.mac"), wallet_account.id(), Some(secret_key)));

            wallet_accounts.push(wallet_account);
        }

        let mut all_accounts = Vec::<Account>::new();
        // Set each faucet supply after all wallet allocations are known.
        for (symbol, mut faucet_account) in faucet_accounts {
            let faucet_id = faucet_account.id();
            // The native supply includes the amount recorded in the imported faucet.
            let total_issuance = faucet_issuance.get(&faucet_id).copied().unwrap_or_default();

            if total_issuance != 0 {
                let current_faucet = FungibleFaucet::try_from(faucet_account.storage())?;
                let new_token_supply = AssetAmount::new(total_issuance)?;
                let max_supply = current_faucet.max_supply().as_u64();
                if max_supply < total_issuance {
                    return Err(GenesisConfigError::MaxIssuanceExceeded {
                        max_supply,
                        symbol: symbol.clone(),
                        total_issuance,
                    });
                }
                let updated_faucet = current_faucet.with_token_supply(new_token_supply)?;
                let slot = updated_faucet.token_config_slot_value();
                faucet_account.storage_mut().set_item(slot.name(), slot.value())?;
                debug!(
                    target: LOG_TARGET,
                    "Setting faucet account issuance",
                    account.id = faucet_id,
                    asset.symbol = symbol.to_string(),
                    asset.amount = total_issuance
                );
            } else {
                debug!(
                    target: LOG_TARGET,
                    "No wallet references faucet asset",
                    account.id = faucet_id,
                    asset.symbol = symbol.to_string()
                );
            }

            if faucet_id != native_faucet_account_id {
                faucet_account.set_nonce(ONE)?;
            }

            all_accounts.push(faucet_account);
        }
        all_accounts.push(funding_account);

        // Ensure the faucets always precede the wallets referencing them
        all_accounts.extend(wallet_accounts);

        // Append file-loaded accounts as-is
        all_accounts.extend(file_loaded_accounts);

        let mut account_ids = std::collections::HashSet::new();
        for account in &all_accounts {
            if !account_ids.insert(account.id()) {
                return Err(GenesisConfigError::DuplicateAccount { account_id: account.id() });
            }
        }

        // Each generated account needs a distinct output file.
        let mut file_names: Vec<&str> = secrets.iter().map(|(name, ..)| name.as_str()).collect();
        file_names.sort_unstable();
        if let Some(pair) = file_names.windows(2).find(|pair| pair[0] == pair[1]) {
            return Err(GenesisConfigError::DuplicateAccountFileName { name: pair[0].to_string() });
        }

        Ok((
            GenesisState {
                fee_parameters,
                accounts: all_accounts,
                timestamp,
                validator_config,
                protocol_config,
            },
            AccountSecrets { secrets },
        ))
    }
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
    account_type: AccountTypeConfig,
}

impl FungibleFaucetConfig {
    /// Create a fungible faucet from a config entry
    fn build_account(self) -> Result<(Account, RpoSecretKey), GenesisConfigError> {
        let FungibleFaucetConfig {
            symbol,
            decimals,
            max_supply,
            account_type,
        } = self;
        let mut rng = ChaCha20Rng::from_seed(rand::random());
        let secret_key = RpoSecretKey::with_rng(&mut rng);
        let auth = AuthSingleSig::new(Approver::new(
            secret_key.public_key().into(),
            AuthScheme::Falcon512Poseidon2,
        ));
        let init_seed: [u8; 32] = rng.random();

        let faucet = FungibleFaucet::builder()
            .name(
                TokenName::new(&symbol.to_string())
                    .expect("token symbol fits within token name byte limit"),
            )
            .symbol(symbol.as_ref().clone())
            .decimals(decimals)
            .max_supply(AssetAmount::new(max_supply)?)
            .build()?;

        // It's similar to `fn create_basic_fungible_faucet`, but we need to cover more cases.
        let faucet_account = AccountBuilder::new(init_seed)
            .account_type(account_type.into())
            .with_component(auth)
            .with_component(faucet)
            .with_components(
                TokenPolicyManager::builder()
                    .active_mint_policy(MintPolicy::allow_all())
                    .active_burn_policy(BurnPolicy::allow_all())
                    .build(),
            )
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
    /// Stem of the account file written for this wallet.
    name: String,
    #[serde(default)]
    account_type: AccountTypeConfig,
    /// Signature scheme of the account's authentication component, named as [`AuthScheme`] writes
    /// it. Defaults to `Falcon512Poseidon2`.
    #[serde(default)]
    auth_scheme: Option<String>,
    assets: Vec<AssetEntry>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct AssetEntry {
    symbol: TokenSymbolStr,
    /// The amount of the given asset, in base units.
    amount: u64,
}

// ACCOUNT TYPE CONFIG
// ================================================================================================

/// See the [full description](https://0xmiden.github.io/miden-protocol/account.html?highlight=Accoun#account-storage-mode)
/// for details
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, Default)]
pub enum AccountTypeConfig {
    /// A publicly stored account, lives on-chain.
    #[serde(alias = "public")]
    Public,
    /// A private account, which must be known by interactors.
    #[serde(alias = "private")]
    #[default]
    Private,
}

impl From<AccountTypeConfig> for AccountType {
    fn from(value: AccountTypeConfig) -> AccountType {
        match value {
            AccountTypeConfig::Public => AccountType::Public,
            AccountTypeConfig::Private => AccountType::Private,
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
    // name, account, private key of the account, if it has one
    pub secrets: Vec<(String, AccountId, Option<AuthSecretKey>)>,
}

impl AccountSecrets {
    /// Convert the internal tuple into an `AccountFile`
    ///
    /// If no name is present, a new one is generated based on the current time
    /// and the index in
    pub fn as_account_files(
        &self,
        genesis_state: &GenesisState,
    ) -> impl Iterator<Item = Result<AccountFileWithName, GenesisConfigError>> + '_ {
        let account_lut = genesis_state
            .accounts
            .iter()
            .map(|account| (account.id(), account.clone()))
            .collect::<IndexMap<AccountId, Account>>();
        self.secrets.iter().cloned().map(move |(name, account_id, secret_key)| {
            let account = account_lut
                .get(&account_id)
                .ok_or(GenesisConfigError::MissingGenesisAccount { account_id })?;
            let auth_secret_keys = secret_key.into_iter().collect();
            let account_file = AccountFile::new(account.clone(), auth_secret_keys);
            Ok(AccountFileWithName { name, account_file })
        })
    }
}

// HELPERS
// ================================================================================================

/// Build wallet assets and add their amounts to each faucet's supply.
fn prepare_fungible_asset_update(
    assets: impl IntoIterator<Item = AssetEntry>,
    faucets: &IndexMap<TokenSymbolStr, Account>,
    faucet_issuance: &mut IndexMap<AccountId, u64>,
) -> Result<Vec<Asset>, GenesisConfigError> {
    assets
        .into_iter()
        .map(|AssetEntry { amount, symbol }| {
            let faucet_account = faucets.get(&symbol).ok_or_else(|| {
                GenesisConfigError::MissingFaucetDefinition { symbol: symbol.clone() }
            })?;
            let faucet_id = faucet_account.id();

            let issuance: &mut u64 = faucet_issuance.entry(faucet_id).or_default();
            debug!(
                target: LOG_TARGET,
                "Updating faucet issuance",
                account.id = faucet_id,
                asset.symbol = symbol.to_string(),
                asset.amount = amount
            );
            issuance
                .checked_add_assign(&amount)
                .map_err(|_| GenesisConfigError::IssuanceOverflow)?;

            Ok(FungibleAsset::new(faucet_id, amount)?.into())
        })
        .collect()
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

impl From<TokenSymbol> for TokenSymbolStr {
    fn from(symbol: TokenSymbol) -> Self {
        let raw = symbol.to_string();
        Self { raw, encoded: symbol }
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
