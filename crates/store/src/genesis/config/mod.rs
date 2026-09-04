//! Describe a subset of the genesis manifest in easily human readable format

use std::cmp::Ordering;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use indexmap::IndexMap;
use miden_node_tracing::debug;
use miden_protocol::account::auth::{AuthScheme, AuthSecretKey};
use miden_protocol::account::{Account, AccountBuilder, AccountFile, AccountId, AccountType};
use miden_protocol::asset::{Asset, AssetAmount, FungibleAsset, TokenSymbol};
use miden_protocol::block::{FeeParameters, ValidatorKeys};
use miden_protocol::crypto::dsa::falcon512_poseidon2::SecretKey as RpoSecretKey;
use miden_protocol::errors::TokenSymbolError;
use miden_protocol::{Felt, ONE};
use miden_standards::account::auth::{Approver, AuthSingleSig, NetworkAccountNoteAllowlist};
use miden_standards::account::faucets::{
    FungibleFaucet,
    TokenName,
    create_native_fungible_faucet_for_genesis,
};
use miden_standards::account::fees::BasicConstantFeePolicy;
use miden_standards::account::policies::{
    BurnPolicy,
    MintPolicy,
    TokenPolicyManager,
    TransferPolicy,
};
use miden_standards::account::wallets::create_basic_wallet;
use miden_standards::note::{BurnNote, FeeSponsorshipNote, MintNote};
use rand::distr::weighted::Weight;
use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};

use crate::genesis::pass_through::build_pass_through_account;
use crate::{GenesisState, LOG_TARGET};

mod errors;
use self::errors::GenesisConfigError;

#[cfg(test)]
mod tests;

const DEFAULT_NATIVE_FAUCET_SYMBOL: &str = "MIDEN";
const DEFAULT_NATIVE_FAUCET_DECIMALS: u8 = 6;
const DEFAULT_NATIVE_FAUCET_MAX_SUPPLY: u64 = 100_000_000_000_000_000;
/// One thousand native tokens, used to bootstrap the operator's fee payments.
const DEFAULT_FAUCET_OPERATOR_BALANCE: u64 = 1_000_000_000;

/// Name of the account file written for the generated native faucet.
pub const NATIVE_FAUCET_FILE_NAME: &str = "native_faucet.mac";

/// Name of the account file written for the generated faucet operator.
pub const FAUCET_OPERATOR_FILE_NAME: &str = "faucet_operator.mac";

/// Name of the account file written for the pass-through account.
pub const PASS_THROUGH_ACCOUNT_FILE_NAME: &str = "pass_through.mac";

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

/// Specify a set of faucets and wallets with assets for easier test deployments.
///
/// Notice: Any faucet must be declared _before_ it's use in a wallet/regular account.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisConfig {
    version: u32,
    timestamp: u32,
    /// Override the native faucet with a custom faucet account.
    ///
    /// If unspecified, the native faucet is generated as a network account owned by a generated
    /// faucet operator account, using:
    ///
    /// ```toml
    /// symbol     = "MIDEN"
    /// decimals   = 6
    /// max_supply = 100_000_000_000_000_000
    /// ```
    ///
    /// The generated operator is pre-funded with 1,000 MIDEN tokens so it can pay the fees required
    /// to submit the first mint requests.
    #[serde(default)]
    native_faucet: Option<PathBuf>,
    fee_parameters: FeeParameterConfig,
    #[serde(default)]
    wallet: Vec<WalletConfig>,
    #[serde(default)]
    fungible_faucet: Vec<FungibleFaucetConfig>,
    #[serde(default)]
    account: Vec<GenericAccountConfig>,
    #[serde(skip)]
    config_dir: PathBuf,
}

impl Default for GenesisConfig {
    fn default() -> Self {
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
            native_faucet: None,
            fee_parameters: FeeParameterConfig { verification_base_fee: 0 },
            fungible_faucet: vec![],
            account: vec![],
            config_dir: PathBuf::from("."),
        }
    }
}

impl GenesisConfig {
    /// Read the genesis config from a TOML file.
    ///
    /// The parent directory of `path` is used to resolve relative paths for account files
    /// referenced in the configuration (e.g., `[[account]]` entries with `path` fields).
    ///
    /// Notice: It will generate the specified case during [`fn into_state`].
    pub fn read_toml_file(path: &Path) -> Result<Self, GenesisConfigError> {
        let toml_str = fs_err::read_to_string(path)
            .map_err(|e| GenesisConfigError::ConfigFileRead(e, path.to_path_buf()))?;
        let config_dir = path.parent().expect("config file path must have a parent directory");
        Self::read_toml(&toml_str, config_dir)
    }

    /// Parse a genesis config from a TOML formatted string.
    ///
    /// The `config_dir` parameter is stored so that relative paths for account files
    /// (e.g., `[[account]]` entries with `path` fields, or native faucet file references)
    /// can be resolved later during [`Self::into_state`].
    fn read_toml(toml_str: &str, config_dir: &Path) -> Result<Self, GenesisConfigError> {
        let mut config: Self = toml::from_str(toml_str)?;
        config.config_dir = config_dir.to_path_buf();
        Ok(config)
    }

    /// Convert the in memory representation into the new genesis state
    ///
    /// The given `validator_keys` are the genesis validator set committed to by the genesis
    /// header. The genesis block is not signed; the committed set is required to sign every block
    /// after genesis.
    ///
    /// Also returns the set of secrets for the generated accounts.
    #[expect(clippy::too_many_lines)]
    pub fn into_state(
        self,
        validator_keys: ValidatorKeys,
    ) -> Result<(GenesisState, AccountSecrets), GenesisConfigError> {
        let GenesisConfig {
            version,
            timestamp,
            native_faucet,
            fee_parameters,
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
                Ok(account_file.account)
            })
            .collect::<Result<Vec<_>, GenesisConfigError>>()?;

        let mut wallet_accounts = Vec::<Account>::new();
        // Every asset sitting in a wallet, has to reference a faucet for that asset
        let mut faucet_accounts = IndexMap::<TokenSymbolStr, Account>::new();

        // Collect the generated secret keys for the test, so one can interact with those
        // accounts/sign transactions
        let mut secrets = Vec::new();

        // Handle native faucet: generate a network faucet and its operator, or load from file
        let NativeFaucet {
            account: native_faucet_account,
            symbol,
            operator,
        } = NativeFaucetConfig(native_faucet).build_account(&config_dir)?;
        let native_faucet_account_id = native_faucet_account.id();

        // Track all genesis issuance, one entry per faucet account id. A generated faucet operator
        // is pre-funded in `NativeFaucetConfig::build_account`, so account for that allocation
        // before adding configured wallet balances below.
        let mut faucet_issuance = IndexMap::<AccountId, u64>::new();
        if operator.is_some() {
            faucet_issuance.insert(native_faucet_account_id, DEFAULT_FAUCET_OPERATOR_BALANCE);
        }

        let operator_account = match operator {
            Some((operator, operator_secret)) => {
                // The generated faucet is a network account and holds no key of its own, but
                // consumers still need its state and id, so it is written out like any other
                // generated account.
                secrets.push((
                    NATIVE_FAUCET_FILE_NAME.to_string(),
                    native_faucet_account.id(),
                    None,
                ));
                secrets.push((
                    FAUCET_OPERATOR_FILE_NAME.to_string(),
                    operator.id(),
                    Some(operator_secret),
                ));
                Some(operator)
            },
            None => None,
        };

        let pass_through_account =
            build_pass_through_account().map_err(GenesisConfigError::PassThroughAccountBuild)?;
        secrets.push((PASS_THROUGH_ACCOUNT_FILE_NAME.to_string(), pass_through_account.id(), None));

        faucet_accounts.insert(symbol.clone(), native_faucet_account);

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
                Some(secret_key),
            ));
            // Do _not_ collect the account, only after we know all wallet assets we know the
            // remaining supply in the faucets.
        }

        let fee_parameters =
            FeeParameters::new(native_faucet_account_id, fee_parameters.verification_base_fee);

        let zero_padding_width = usize::ilog10(std::cmp::max(10, wallet_configs.len())) as usize;

        // Setup all wallet accounts, which reference the faucet's for their provided assets.
        for (index, WalletConfig { account_type, assets }) in wallet_configs.into_iter().enumerate()
        {
            debug!(
                target: LOG_TARGET,
                "Adding wallet account",
                account.index = index,
                account.assets.count = assets.len()
            );

            let mut rng = ChaCha20Rng::from_seed(rand::random());
            let secret_key = RpoSecretKey::with_rng(&mut rng);
            let auth =
                Approver::new(secret_key.public_key().into(), AuthScheme::Falcon512Poseidon2);
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

            secrets.push((
                format!("wallet_{index:0zero_padding_width$}.mac"),
                wallet_account.id(),
                Some(secret_key),
            ));

            wallet_accounts.push(wallet_account);
        }

        let mut all_accounts = Vec::<Account>::new();
        // Apply all fungible faucet adjustments to the respective faucet
        for (symbol, mut faucet_account) in faucet_accounts {
            let faucet_id = faucet_account.id();
            // If there is no account using the asset, we only bump the nonce to `ONE`.
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
                    "Reducing faucet account issuance",
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

            // Force the account nonce to 1, marking the faucet as deployed at genesis.
            faucet_account.set_nonce(ONE)?;

            debug_assert_eq!(faucet_account.nonce(), ONE);

            // sanity check the total issuance against
            let faucet = FungibleFaucet::try_from(faucet_account.storage())?;
            let max_supply = faucet.max_supply().as_u64();
            if max_supply < total_issuance {
                return Err(GenesisConfigError::MaxIssuanceExceeded {
                    max_supply,
                    symbol,
                    total_issuance,
                });
            }

            all_accounts.push(faucet_account);
        }
        // Keep the operator after the faucets because its vault references the native faucet.
        all_accounts.extend(operator_account);

        // Ensure the faucets always precede the wallets referencing them
        all_accounts.extend(wallet_accounts);

        all_accounts.push(pass_through_account);

        // Append file-loaded accounts as-is
        all_accounts.extend(file_loaded_accounts);

        Ok((
            GenesisState {
                fee_parameters,
                accounts: all_accounts,
                version,
                timestamp,
                validator_keys,
            },
            AccountSecrets { secrets },
        ))
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

// NATIVE FAUCET CONFIG
// ================================================================================================

/// The native faucet resolved from the configuration.
struct NativeFaucet {
    account: Account,
    symbol: TokenSymbolStr,
    /// The operator account owning the faucet, with its signing key. Only present when the faucet
    /// is generated; an imported faucet comes with its own keys.
    operator: Option<(Account, RpoSecretKey)>,
}

/// Wraps an optional path to a pre-built faucet account file.
///
/// When no path is provided, a network faucet is generated together with the operator account
/// owning it.
struct NativeFaucetConfig(Option<PathBuf>);

impl NativeFaucetConfig {
    /// Build or load the native faucet account.
    ///
    /// For `None`, generates a network faucet plus the operator account owning it, and returns the
    /// operator alongside its signing key.
    ///
    /// For `Some(path)`, loads the account from disk and validates it is a fungible faucet.
    fn build_account(self, config_dir: &Path) -> Result<NativeFaucet, GenesisConfigError> {
        match self.0 {
            None => {
                // The operator is built first, since the faucet it owns commits to its id.
                let (mut operator, operator_secret) = build_faucet_operator()?;
                let (account, symbol) = build_native_faucet(operator.id())?;
                // Now that the faucet id is known, pre-fund the operator so it can pay fees for the
                // first mint requests. Genesis issuance is updated in `into_state`.
                let operator_asset =
                    FungibleAsset::new(account.id(), DEFAULT_FAUCET_OPERATOR_BALANCE)?;
                operator.vault_mut().add_asset(operator_asset.into())?;
                Ok(NativeFaucet {
                    account,
                    symbol,
                    operator: Some((operator, operator_secret)),
                })
            },
            Some(path) => {
                let full_path = config_dir.join(&path);
                let account_file = AccountFile::read(&full_path)
                    .map_err(|e| GenesisConfigError::AccountFileRead(e, full_path.clone()))?;
                let account = account_file.account;

                let faucet = FungibleFaucet::try_from(&account).map_err(|_| {
                    GenesisConfigError::NativeFaucetNotFungible { path: full_path.clone() }
                })?;
                let symbol = TokenSymbolStr::from(faucet.symbol().clone());
                Ok(NativeFaucet { account, symbol, operator: None })
            },
        }
    }
}

// FAUCET OPERATOR
// ================================================================================================

/// Builds the initially assetless faucet operator account and returns it with its signing key.
///
/// Its nonce is set to `1`, marking it as deployed at genesis. The operator is funded after the
/// native faucet is built, because its asset id is not known before then.
fn build_faucet_operator() -> Result<(Account, RpoSecretKey), GenesisConfigError> {
    let mut rng = ChaCha20Rng::from_seed(rand::random());

    let secret_key = RpoSecretKey::with_rng(&mut rng);
    let auth = Approver::new(secret_key.public_key().into(), AuthScheme::Falcon512Poseidon2);
    let init_seed: [u8; 32] = rng.random();
    let mut operator = create_basic_wallet(init_seed, auth, AccountType::Public)?;
    operator.set_nonce(ONE)?;

    Ok((operator, secret_key))
}

// NATIVE FAUCET
// ================================================================================================

/// Builds the native faucet as a network account owned by `operator_id`.
///
/// The faucet is authenticated as a network account and therefore carries no signing key of its
/// own; only the operator can mint from it.
fn build_native_faucet(
    operator_id: AccountId,
) -> Result<(Account, TokenSymbolStr), GenesisConfigError> {
    let mut rng = ChaCha20Rng::from_seed(rand::random());

    let symbol = TokenSymbolStr::from_str(DEFAULT_NATIVE_FAUCET_SYMBOL)?;
    let faucet_component = FungibleFaucet::builder()
        .name(
            TokenName::new(DEFAULT_NATIVE_FAUCET_SYMBOL)
                .expect("token symbol fits within token name byte limit"),
        )
        .symbol(symbol.as_ref().clone())
        .decimals(DEFAULT_NATIVE_FAUCET_DECIMALS)
        .max_supply(AssetAmount::new(DEFAULT_NATIVE_FAUCET_MAX_SUPPLY)?)
        .build()?;

    let policies = TokenPolicyManager::builder()
        .active_mint_policy(MintPolicy::owner_only())
        .active_burn_policy(BurnPolicy::allow_all())
        .active_send_policy(TransferPolicy::allow_all())
        .active_receive_policy(TransferPolicy::allow_all())
        .build();

    let fee_policy = BasicConstantFeePolicy::new().with_fees([
        (MintNote::script_root(), AssetAmount::ZERO),
        (BurnNote::script_root(), AssetAmount::ZERO),
    ]);

    // The faucet charges fees in its own asset; the genesis constructor resolves the self-reference
    // by patching the fee-asset slot after the account id is derived.
    let faucet_seed: [u8; 32] = rng.random();
    let faucet = create_native_fungible_faucet_for_genesis(
        faucet_seed,
        faucet_component,
        operator_id,
        policies,
        fee_policy,
    )?;

    debug_assert_eq!(faucet.nonce(), ONE);

    // The faucet's note allowlist must cover the fee sponsorship note, otherwise the network
    // transaction builder will not work.
    debug_assert!(
        NetworkAccountNoteAllowlist::try_from(faucet.storage()).is_ok_and(|allowlist| {
            allowlist.allowed_script_roots().contains(&FeeSponsorshipNote::script_root())
        }),
        "network faucet's note allowlist must cover the fee sponsorship note"
    );

    Ok((faucet, symbol))
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
    #[serde(default)]
    account_type: AccountTypeConfig,
    assets: Vec<AssetEntry>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct AssetEntry {
    symbol: TokenSymbolStr,
    /// The amount of full token units the given asset is populated with
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
    pub secrets: Vec<(String, AccountId, Option<RpoSecretKey>)>,
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
            let auth_secret_keys =
                secret_key.map(AuthSecretKey::Falcon512Poseidon2).into_iter().collect();
            let account_file = AccountFile::new(account.clone(), auth_secret_keys);
            Ok(AccountFileWithName { name, account_file })
        })
    }
}

// HELPERS
// ================================================================================================

/// Process wallet assets and return them as a fungible asset delta. Track the negative adjustments
/// for the respective faucets.
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

            Ok(Asset::Fungible(FungibleAsset::new(faucet_id, amount)?))
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
