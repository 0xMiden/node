//! The `faucet` command's inputs: the role holders' account ids ([`RoleAccounts`]) and the faucet
//! parameters ([`FaucetConfig`]), both taken from the command line.

use miden_protocol::account::AccountId;
use miden_protocol::asset::AssetAmount;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::PublicKey;
use miden_protocol::utils::serde::Deserializable;
use miden_usdcx::xreserve::encoding::{CircleDomain, DepositNonce};

/// The default faucet seed: the ASCII of `USDCX-FAUCET` zero-padded to 32 bytes.
pub const DEFAULT_FAUCET_SEED: &str =
    "0x55534443582d4641554345540000000000000000000000000000000000000000";

// ROLES
// ================================================================================================

/// The five faucet roles the `XReserveStablecoinBuilder` seeds (`ADMIN`, `ATTEST_ADMIN`,
/// `DOM_PAUSER`, `DOM_UNPAUSER`, `BLK_MANAGER`). `ADMIN` has exactly one holder; the four
/// operational roles take zero or more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Owner,
    AttestAdmin,
    Pauser,
    Unpauser,
    BlocklistManager,
}

impl Role {
    /// Every role, in the stable order the outputs are emitted in.
    pub const ALL: [Role; 5] = [
        Role::Owner,
        Role::AttestAdmin,
        Role::Pauser,
        Role::Unpauser,
        Role::BlocklistManager,
    ];

    /// The role's name in the stdout listing.
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Owner => "owner",
            Role::AttestAdmin => "attest_admins",
            Role::Pauser => "pausers",
            Role::Unpauser => "unpausers",
            Role::BlocklistManager => "blocklist_managers",
        }
    }
}

// CONFIG
// ================================================================================================

/// The `faucet` inputs: the role holders' account ids and the [`FaucetConfig`].
#[derive(Debug, Clone, clap::Args)]
pub struct GenesisToolConfig {
    #[command(flatten)]
    pub accounts: RoleAccounts,
    #[command(flatten)]
    pub faucet: FaucetConfig,
}

/// The role holders' account ids, each id given as `0x`-prefixed hex or as bech32. `owner` is the
/// single `ADMIN` holder; the four operational roles take zero or more holders (none means the role
/// is populated later through the standard role-action note).
#[derive(Debug, Clone, clap::Args)]
pub struct RoleAccounts {
    /// The `ADMIN` holder's account id (hex or bech32): the distributor printed by
    /// `new-distributor`.
    #[arg(long, value_name = "ACCOUNT_ID", value_parser = parse_account_id)]
    pub owner: AccountId,
    /// An `ATTEST_ADMIN` holder's account id; repeat per holder or separate with commas.
    #[arg(
        long = "attest-admin",
        value_name = "ACCOUNT_ID",
        value_delimiter = ',',
        value_parser = parse_account_id
    )]
    pub attest_admins: Vec<AccountId>,
    /// A `DOM_PAUSER` holder's account id; repeat per holder or separate with commas.
    #[arg(
        long = "pauser",
        value_name = "ACCOUNT_ID",
        value_delimiter = ',',
        value_parser = parse_account_id
    )]
    pub pausers: Vec<AccountId>,
    /// A `DOM_UNPAUSER` holder's account id; repeat per holder or separate with commas.
    #[arg(
        long = "unpauser",
        value_name = "ACCOUNT_ID",
        value_delimiter = ',',
        value_parser = parse_account_id
    )]
    pub unpausers: Vec<AccountId>,
    /// A `BLK_MANAGER` holder's account id; repeat per holder or separate with commas.
    #[arg(
        long = "blocklist-manager",
        value_name = "ACCOUNT_ID",
        value_delimiter = ',',
        value_parser = parse_account_id
    )]
    pub blocklist_managers: Vec<AccountId>,
}

impl RoleAccounts {
    /// Returns the account ids configured for `role`.
    pub fn get(&self, role: Role) -> &[AccountId] {
        match role {
            Role::Owner => std::slice::from_ref(&self.owner),
            Role::AttestAdmin => &self.attest_admins,
            Role::Pauser => &self.pausers,
            Role::Unpauser => &self.unpausers,
            Role::BlocklistManager => &self.blocklist_managers,
        }
    }
}

/// The faucet's account seed and the `XReserveStablecoinBuilder` inputs that are not role account
/// ids; amounts are base units.
#[derive(Debug, Clone, clap::Args)]
pub struct FaucetConfig {
    /// The faucet's 32-byte account seed as hex. It feeds the faucet id, so fix it before the
    /// faucet runs.
    #[arg(long, default_value = DEFAULT_FAUCET_SEED, value_parser = parse_seed)]
    pub seed: [u8; 32],
    /// The initial supply in base units (six decimals), recorded as issued and handed to the
    /// distributor by `prefund`. It feeds the faucet id.
    #[arg(long, value_parser = parse_asset_amount)]
    pub token_supply: AssetAmount,
    /// The Circle domain id.
    #[arg(long, default_value_t = CircleDomain::MIDEN)]
    pub domain: CircleDomain,
    /// The smallest amount a burn may redeem, in base units.
    #[arg(long)]
    pub min_burn_amount: Option<u64>,
    /// The verification base fee baked into the faucet's fee schedule. Must equal the
    /// `--verification-base-fee` passed to `build`.
    #[arg(long)]
    pub verification_base_fee: u32,
    /// A deposit attester to allowlist, as the hex of its 33-byte compressed SEC1 public key;
    /// repeat per attester or separate with commas. None means the allowlist is seeded later
    /// through `set_attester` notes.
    #[arg(long = "attester", value_name = "KEY", value_delimiter = ',', value_parser = parse_attester)]
    pub attesters: Vec<PublicKey>,
}

// VALUE PARSERS
// ================================================================================================

/// Parses an account id from its hex or bech32 form.
pub fn parse_account_id(text: &str) -> Result<AccountId, String> {
    AccountId::parse(text).map(|(id, _network)| id).map_err(|err| err.to_string())
}

/// Parses an asset amount from its base-unit integer, rejecting values over the supply cap.
pub fn parse_asset_amount(text: &str) -> Result<AssetAmount, String> {
    let amount: u64 = text.parse().map_err(|err| format!("{err}"))?;
    AssetAmount::new(amount).map_err(|err| err.to_string())
}

/// Parses the faucet seed from its 32-byte hex form.
pub fn parse_seed(text: &str) -> Result<[u8; 32], String> {
    parse_hex_array::<32>(text)
}

/// Parses an attester key from the hex of its 33-byte compressed SEC1 form.
pub fn parse_attester(text: &str) -> Result<PublicKey, String> {
    PublicKey::read_from_bytes(&parse_hex_array::<33>(text)?).map_err(|err| err.to_string())
}

/// Parses a deposit nonce from the hex of its 32 bytes.
pub fn parse_deposit_nonce(text: &str) -> Result<DepositNonce, String> {
    parse_hex_array::<32>(text).map(DepositNonce::new)
}

/// Decodes a hex string (with an optional `0x` prefix) into exactly `N` bytes.
fn parse_hex_array<const N: usize>(text: &str) -> Result<[u8; N], String> {
    let bytes =
        hex::decode(text.strip_prefix("0x").unwrap_or(text)).map_err(|err| err.to_string())?;
    <[u8; N]>::try_from(bytes).map_err(|bytes| format!("expected {N} bytes, got {}", bytes.len()))
}
