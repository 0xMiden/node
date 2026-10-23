//! Test support: a funding account and a fee faucet shaped like the ones genesis creates, on a
//! [`MockChain`].

pub(crate) mod telemetry;

use std::sync::Arc;

use anyhow::{Context, Result};
use miden_node_utils::usdcx_p2id::UsdcxP2Id;
use miden_protocol::account::auth::{AuthScheme, AuthSecretKey};
use miden_protocol::account::{Account, AccountId, AccountType};
use miden_protocol::asset::{AssetAmount, AssetId, FungibleAsset, TokenSymbol};
use miden_protocol::crypto::dsa::falcon512_poseidon2::SecretKey;
use miden_protocol::crypto::rand::RandomCoin;
use miden_protocol::note::{Note, NoteType};
use miden_protocol::{Felt, ONE};
use miden_standards::account::access::AccessControl;
use miden_standards::account::auth::Approver;
use miden_standards::account::faucets::{
    FungibleFaucet as FungibleFaucetComponent,
    TokenName,
    create_network_fungible_faucet,
};
use miden_standards::account::fees::{BasicConstantFeePolicy, FeePolicyManager};
use miden_standards::account::policies::{
    BurnPolicy,
    MintPolicy,
    TokenPolicyManager,
    TransferPolicy,
};
use miden_standards::account::wallets::create_basic_wallet;
use miden_standards::note::{BurnNote, MintNote, P2idNote};
use miden_testing::MockChain;
use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha20Rng;
use tokio::sync::Mutex;

use crate::account::FundingWallet;
use crate::status::NativeAsset;

/// The base fee used by the tests which exercise the fee path.
pub const TEST_BASE_FEE: u32 = 500;

// ACCOUNTS
// ================================================================================================

/// Builds a public wallet the way the genesis configuration does, prefunded with `balance` of the
/// native asset.
pub fn genesis_style_wallet(
    fee_faucet_id: AccountId,
    balance: u64,
    seed: [u8; 32],
) -> Result<(Account, SecretKey)> {
    let mut rng = ChaCha20Rng::from_seed(seed);
    let secret_key = SecretKey::with_rng(&mut rng);
    let auth = Approver::new(secret_key.public_key().into(), AuthScheme::Falcon512Poseidon2);
    let init_seed: [u8; 32] = rng.random();

    let mut wallet = create_basic_wallet(init_seed, auth, AccountType::Public)?;
    if balance > 0 {
        wallet
            .vault_mut()
            .add_asset(FungibleAsset::new(fee_faucet_id, balance)?.into())?;
    }
    wallet.set_nonce(ONE)?;

    Ok((wallet, secret_key))
}

/// Builds the native asset metadata of the mock issuer, with a name and a symbol which differ.
pub fn test_native_asset() -> NativeAsset {
    let faucet = FungibleFaucetComponent::builder()
        .name(TokenName::new("Miden").expect("valid token name"))
        .symbol(TokenSymbol::new("MIDEN").expect("valid token symbol"))
        .decimals(6)
        .max_supply(AssetAmount::new(100_000_000_000_000_000).expect("valid supply"))
        .build()
        .expect("valid faucet");

    NativeAsset::new(AssetId::new_fungible(FungibleAsset::mock_issuer()), &faucet)
}

fn native_faucet_with_transfer_policy(
    operator: AccountId,
    seed: [u8; 32],
    transfer_policy: TransferPolicy,
) -> Result<Account> {
    let faucet_component = FungibleFaucetComponent::builder()
        .name(TokenName::new("MIDEN").expect("valid token name"))
        .symbol(TokenSymbol::new("MIDEN").expect("valid token symbol"))
        .decimals(6)
        .max_supply(AssetAmount::new(100_000_000_000_000_000).expect("valid supply"))
        .build()?;
    let policies = TokenPolicyManager::builder()
        .active_mint_policy(MintPolicy::owner_only())
        .active_burn_policy(BurnPolicy::allow_all())
        .active_send_policy(transfer_policy.clone())
        .active_receive_policy(transfer_policy)
        .build();
    let fee_policy = BasicConstantFeePolicy::new()
        .with_fees([
            (MintNote::script_root(), AssetAmount::ZERO),
            (BurnNote::script_root(), AssetAmount::ZERO),
        ])
        .into();
    let fee_policy_manager = FeePolicyManager::builder()
        .fee_faucet_id(operator)
        .active_fee_policy(fee_policy)
        .build();

    let mut faucet = create_network_fungible_faucet(
        seed,
        faucet_component,
        AccessControl::Ownable2Step { owner: operator },
        policies,
        fee_policy_manager,
    )?;
    // Mark the faucet as deployed, the same way genesis does, so the mock chain accepts it.
    faucet.set_nonce(Felt::ONE)?;

    Ok(faucet)
}

// MOCK CHAIN FIXTURE
// ================================================================================================

/// A mock chain which holds a prefunded funding wallet and the native faucet.
pub struct Fixture {
    pub chain: Arc<Mutex<MockChain>>,
    pub funder: Account,
    pub wallet: FundingWallet,
    pub fee_faucet_id: AccountId,
}

impl Fixture {
    /// Builds a chain which charges `base_fee` and holds a funding wallet with `balance`.
    pub fn new(balance: u64, base_fee: u32) -> Result<Self> {
        Self::with_transfer_policy(balance, base_fee, TransferPolicy::allow_all())
    }

    /// Builds a funding fixture with the same transfer policy for sending and receiving assets.
    pub fn with_transfer_policy(
        balance: u64,
        base_fee: u32,
        policy: TransferPolicy,
    ) -> Result<Self> {
        // The faucet's owner does not matter for these tests, so the wallet built first stands in.
        let (owner, _) = genesis_style_wallet(FungibleAsset::mock_issuer(), 0, [1; 32])?;
        let faucet = native_faucet_with_transfer_policy(owner.id(), [7; 32], policy)?;
        let fee_faucet_id = faucet.id();

        let (funder, secret_key) = genesis_style_wallet(fee_faucet_id, balance, [9; 32])?;
        let wallet = FundingWallet::new(
            funder.clone(),
            AuthSecretKey::Falcon512Poseidon2(secret_key),
            AssetId::new_fungible(fee_faucet_id),
        );

        let mut builder = MockChain::builder()
            .fee_faucet_id(fee_faucet_id)
            .verification_base_fee(base_fee);
        builder.add_account(faucet)?;
        builder.add_account(funder.clone())?;
        let chain = builder.build()?;

        Ok(Self {
            chain: Arc::new(Mutex::new(chain)),
            funder,
            wallet,
            fee_faucet_id,
        })
    }
}

// NOTE CREATION
// ================================================================================================

/// Builds a public P2ID note which holds `amount` base units of the fee asset and targets `target`.
pub fn build_funding_note(
    sender: AccountId,
    fee_asset_id: AssetId,
    target: AccountId,
    amount: u64,
    rng: &mut RandomCoin,
) -> Result<UsdcxP2Id> {
    let asset = FungibleAsset::new(fee_asset_id.faucet_id(), amount)
        .context("failed to build the funding asset")?;
    let note: Note = P2idNote::builder()
        .sender(sender)
        .target(target)
        .asset(asset)
        .note_type(NoteType::Public)
        .generate_serial_number(rng)
        .build()
        .context("failed to build the funding note")?
        .into();

    UsdcxP2Id::from_note(note, fee_asset_id).context("the funding note must be a USDCx P2ID note")
}
