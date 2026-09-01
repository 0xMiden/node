//! Account construction for the seeded faucet + wallet + counter set.
//!
//! Self-contained by design: the assembly under `src/assets/`, the storage slot names, the component
//! paths, and the build order all live here, so this tool depends on nothing outside its own crate.
//!
//! Two internal invariants tie these accounts to the increment driver in [`crate::increment`]:
//!
//! - the counter's note allowlist must contain the root of the increment note script, pinned as
//!   `INCREMENT_NOTE_SCRIPT_ROOT` in this module's tests, and
//! - the wallet must expose `increment_and_create_note` at [`WALLET_COUNTER_COMPONENT_PATH`], which
//!   the increment transaction script `call`s.
//!
//! Both derive from the assembly here, and both sides of each pair are built from the same constants,
//! so they cannot disagree within this binary. The pinned root exists to catch an accidental edit to
//! the assembly, which would otherwise only surface as rejected notes on a live chain.

use std::sync::LazyLock;

use anyhow::{Context, Result};
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountComponentCode,
    AccountId,
    AccountType,
    StorageMap,
    StorageMapKey,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::asset::{AssetAmount, TokenSymbol};
use miden_protocol::crypto::dsa::falcon512_poseidon2::SecretKey;
use miden_protocol::note::NoteScript;
use miden_protocol::{Felt, Word};
use miden_standards::account::auth::{Approver, AuthNetworkAccount, AuthSingleSig};
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use miden_standards::account::fees::{BasicConstantFeePolicy, FeePolicyManager};
use miden_standards::account::policies::{BurnPolicy, MintPolicy, TokenPolicyManager};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::tx_script::ExpirationTransactionScript;
use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha20Rng;

// MASM SOURCES
// ================================================================================================

/// The counter account's program (also linked into the increment note script).
const COUNTER_PROGRAM: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/assets/counter_program.masm"));

/// The wallet self-counter component source.
const WALLET_COUNTER_PROGRAM: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/assets/wallet_counter_program.masm"));

/// The increment note script source.
const INCREMENT_COUNTER_NOTE: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/assets/increment_counter.masm"));

// STORAGE SLOT NAMES
// ================================================================================================

/// Storage slot on the wallet holding the number of increment transactions it has committed.
static WALLET_COUNTER_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::monitor::wallet_contract::counter")
        .expect("storage slot name should be valid")
});

/// Storage slot on the counter account holding the owner's account id.
static OWNER_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::monitor::counter_contract::owner")
        .expect("storage slot name should be valid")
});

/// Name of the storage slot on the counter account holding the counter value. Exposed as a string
/// so the value can be read back from RPC by name.
pub const COUNTER_SLOT: &str = "miden::monitor::counter_contract::counter";

/// Storage slot on the counter account holding the counter value.
static COUNTER_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new(COUNTER_SLOT).expect("storage slot name should be valid")
});

/// Storage slot holding the large map that makes the account oversized. The counter's own logic
/// never touches this slot, but the ntx-builder must load the full account — map included — to
/// build every increment transaction, which is the whole point of the benchmark.
static BIG_MAP_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::monitor::counter_contract::big_map")
        .expect("storage slot name should be valid")
});

/// Module path under which the wallet's self-counter component is compiled. The increment
/// transaction script `call`s `increment_and_create_note` under this exact path, so the call
/// resolves to the procedure root the account registered.
pub const WALLET_COUNTER_COMPONENT_PATH: &str = "wallet::program";

/// Compiles the wallet's self-counter component code.
///
/// Both the account builder and the increment transaction script go through here: the script
/// dynamically links this code so its `call` resolves to the same procedure root the account
/// registered. Compilation is deterministic, so both sites get identical code.
pub fn wallet_counter_component_code() -> Result<AccountComponentCode> {
    CodeBuilder::default()
        .compile_component_code(WALLET_COUNTER_COMPONENT_PATH, WALLET_COUNTER_PROGRAM)
        .context("failed to compile wallet counter component code")
}

// FEE FAUCET
// ================================================================================================

/// Token symbol of the seeded fee faucet. Matches the genesis default so a run reads the same as a
/// stock local network.
const FEE_FAUCET_SYMBOL: &str = "MIDEN";
/// Decimals of the seeded fee faucet, matching the genesis default.
const FEE_FAUCET_DECIMALS: u8 = 6;
/// Max supply of the seeded fee faucet, matching the genesis default.
const FEE_FAUCET_MAX_SUPPLY: u64 = 100_000_000_000_000_000;

/// Creates the fungible faucet that fees are denominated in. Returns the account and its signing
/// key.
///
/// The account is left at nonce zero, as a freshly generated account. Genesis bumps it to one when
/// it commits it, exactly as it does for a faucet it generated itself.
pub fn create_fee_faucet_account() -> Result<(Account, SecretKey)> {
    let mut rng = ChaCha20Rng::from_seed(rand::random());
    let secret_key = SecretKey::with_rng(&mut rng);
    let auth = AuthSingleSig::new(Approver::new(
        secret_key.public_key().into(),
        AuthScheme::Falcon512Poseidon2,
    ));
    let init_seed: [u8; 32] = rng.random();

    let symbol =
        TokenSymbol::new(FEE_FAUCET_SYMBOL).context("fee faucet symbol should be valid")?;
    let faucet = FungibleFaucet::builder()
        .name(TokenName::new(FEE_FAUCET_SYMBOL).context("fee faucet name should be valid")?)
        .symbol(symbol)
        .decimals(FEE_FAUCET_DECIMALS)
        .max_supply(AssetAmount::new(FEE_FAUCET_MAX_SUPPLY)?)
        .build()
        .context("failed to build the fee faucet component")?;

    let account = AccountBuilder::new(init_seed)
        .account_type(AccountType::Public)
        .with_component(auth)
        .with_component(faucet)
        .with_components(
            TokenPolicyManager::builder()
                .active_mint_policy(MintPolicy::allow_all())
                .active_burn_policy(BurnPolicy::allow_all())
                .build(),
        )
        .build()
        .context("failed to build the fee faucet account")?;

    Ok((account, secret_key))
}

// WALLET
// ================================================================================================

/// Creates the owner wallet: Falcon512 auth plus the self-counter component the increment
/// transaction script calls into. Returns the account and its signing key.
pub fn create_wallet_account() -> Result<(Account, SecretKey)> {
    let mut rng = ChaCha20Rng::from_seed(rand::random());
    let secret_key = SecretKey::with_rng(&mut rng);
    let auth_component: AccountComponent = AuthSingleSig::new(Approver::new(
        secret_key.public_key().into(),
        AuthScheme::Falcon512Poseidon2,
    ))
    .into();
    let init_seed: [u8; 32] = rng.random();

    let component_code = wallet_counter_component_code()?;

    let counter_slot = StorageSlot::with_value(WALLET_COUNTER_SLOT_NAME.clone(), Word::empty());
    let metadata = AccountComponentMetadata::new(WALLET_COUNTER_COMPONENT_PATH);
    let counter_component = AccountComponent::new(component_code, vec![counter_slot], metadata)?;

    let account = AccountBuilder::new(init_seed)
        .account_type(AccountType::Public)
        .with_component(auth_component)
        .with_component(counter_component)
        .build()
        .context("failed to build wallet account")?;

    Ok((account, secret_key))
}

// COUNTER
// ================================================================================================

/// Compiles the increment note script whose root must appear in the counter's note allowlist.
pub fn create_increment_script() -> Result<NoteScript> {
    CodeBuilder::new()
        .with_linked_module("external_contract::counter_contract", COUNTER_PROGRAM)
        .context("failed to create script builder with library")?
        .compile_note_script(INCREMENT_COUNTER_NOTE)
        .context("failed to compile note script")
}

/// Builds the large storage-map slot, keyed `[i, 0, 0, 0]`. Returns an empty vector when `entries` is
/// zero.
///
/// The values carry no meaning and nothing ever reads them. The counter's own logic never touches
/// this slot. The one requirement is that they are not all-zero, since a zero value denotes deletion
/// in the underlying SMT and the entry would not be stored at all: hence the trailing `1`.
fn counter_big_map_slots(entries: u32) -> Vec<StorageSlot> {
    if entries == 0 {
        return Vec::new();
    }

    let map_entries: Vec<(StorageMapKey, Word)> = (0..entries)
        .map(|i| (StorageMapKey::from_index(i), Word::from([i, 0, 0, 1])))
        .collect();

    let map = StorageMap::with_entries(map_entries).expect("map entries should be valid");
    vec![StorageSlot::with_map(BIG_MAP_SLOT_NAME.clone(), map)]
}

/// Creates the network counter account owned by `owner_account_id`, with `big_map_entries` entries
/// pre-populated into its benchmark storage map.
///
/// `fee_faucet_id` must be the faucet the chain's `fee_parameters` name, otherwise the account
/// prices its notes in an asset the network does not settle in. See
/// [`create_fee_faucet_account`] for how the two are kept in agreement.
pub fn create_counter_account(
    owner_account_id: AccountId,
    fee_faucet_id: AccountId,
    big_map_entries: u32,
) -> Result<Account> {
    let owner_account_id_prefix = owner_account_id.prefix().as_felt();
    let owner_account_id_suffix = owner_account_id.suffix();

    let owner_id_slot = StorageSlot::with_value(
        OWNER_SLOT_NAME.clone(),
        Word::from([owner_account_id_suffix, owner_account_id_prefix, Felt::ZERO, Felt::ZERO]),
    );
    let counter_slot = StorageSlot::with_value(COUNTER_SLOT_NAME.clone(), Word::empty());

    let component_code = CodeBuilder::default()
        .compile_component_code("counter::program", COUNTER_PROGRAM)
        .context("failed to compile counter component code")?;

    // The counter's own two value slots, followed by the large benchmark map slot.
    // `AccountComponent::new` only bounds the slot count (<256); the map slot need not be
    // referenced by the component MASM.
    let mut storage_slots = vec![counter_slot, owner_id_slot];
    storage_slots.extend(counter_big_map_slots(big_map_entries));

    let metadata = AccountComponentMetadata::new("counter::program");
    let account_code = AccountComponent::new(component_code, storage_slots, metadata)?;

    let increment_script = create_increment_script()?;
    let allowed_scripts = [increment_script.root()].into_iter().collect();

    let fee_policy = BasicConstantFeePolicy::new()
        .with_fees([(increment_script.root(), AssetAmount::ZERO)])
        .into();
    let fee_policy_manager = FeePolicyManager::builder()
        .fee_faucet_id(fee_faucet_id)
        .active_fee_policy(fee_policy)
        .build();

    let allowed_tx_scripts = [ExpirationTransactionScript::script_root()];
    let network_account_auth = AuthNetworkAccount::custom(allowed_scripts, fee_policy_manager)
        .expect("list is not empty")
        .with_allowed_tx_scripts(allowed_tx_scripts);

    let init_seed: [u8; 32] = rand::random();
    AccountBuilder::new(init_seed)
        .account_type(AccountType::Public)
        .with_component(account_code)
        .with_components(network_account_auth)
        .build()
        .context("failed to build counter account")
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::asset::AssetId;
    use miden_standards::account::auth::NetworkAccount;

    use super::*;

    /// The increment note script root.
    const INCREMENT_NOTE_SCRIPT_ROOT: &str =
        "0xc402578ca320d0d6361e06a180ebb5857b9ab645cb76760096ded3dcdd7845df";

    #[test]
    fn increment_note_script_root_is_unchanged() {
        let root = create_increment_script().expect("increment script should compile").root();

        assert_eq!(
            root.to_string(),
            INCREMENT_NOTE_SCRIPT_ROOT,
            "the increment note script root changed; accounts seeded from this version will reject \
             increment notes built from a different copy of the assembly",
        );
    }

    /// Both accounts must assemble, and the counter must be buildable with a populated map. A small
    /// entry count keeps this fast while still exercising the map-slot path.
    #[test]
    fn accounts_build_with_and_without_a_populated_map() {
        let (wallet, _secret_key) = create_wallet_account().expect("wallet should build");
        let (faucet, _faucet_key) = create_fee_faucet_account().expect("faucet should build");

        let small = create_counter_account(wallet.id(), faucet.id(), 0)
            .expect("counter should build empty");
        let big = create_counter_account(wallet.id(), faucet.id(), 64)
            .expect("counter should build with a map");

        // Assert the delta rather than absolute counts, which also include the auth component's
        // slots: a populated map must add exactly one slot, and an empty one must add none.
        assert_eq!(
            big.storage().slots().len(),
            small.storage().slots().len() + 1,
            "a populated map should add exactly one storage slot",
        );
    }

    /// Every note script the counter allowlists must also be priced: a script without a schedule
    /// entry aborts fee estimation.
    #[test]
    fn every_allowlisted_note_script_is_priced_at_zero() {
        let (wallet, _secret_key) = create_wallet_account().expect("wallet should build");
        let (faucet, _faucet_key) = create_fee_faucet_account().expect("faucet should build");
        let counter =
            create_counter_account(wallet.id(), faucet.id(), 0).expect("counter should build");

        let allowlisted = NetworkAccount::new(counter.clone())
            .expect("counter should be a valid network account")
            .allowed_notes()
            .allowed_script_roots()
            .clone();
        assert_eq!(
            allowlisted.len(),
            1,
            "only the increment note may be allowlisted, got {allowlisted:?}"
        );

        // A scheduled entry is `[fee_amount, 0, 0, 1]`: the trailing set-marker is what
        // distinguishes an explicit zero fee from an absent key, since storage maps prune zero
        // words and return the zero word for anything unset.
        let expected_entry = Word::from([Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::ONE]);
        for root in &allowlisted {
            let entry = counter
                .storage()
                .get_map_item(
                    BasicConstantFeePolicy::fee_schedule_slot_name(),
                    StorageMapKey::new(root.as_word()),
                )
                .expect("the fee schedule slot should be a map");
            assert_eq!(
                entry, expected_entry,
                "note script root {root} is allowlisted but has no zero-fee schedule entry"
            );
        }
    }

    /// The counter must price its notes in the seeded faucet's asset, which the genesis
    /// configuration adopts as the chain's native asset via `native_faucet`. If the two drift, the
    /// account settles in an asset the network does not.
    #[test]
    fn counter_prices_notes_in_the_seeded_faucet_asset() {
        let (wallet, _secret_key) = create_wallet_account().expect("wallet should build");
        let (faucet, _faucet_key) = create_fee_faucet_account().expect("faucet should build");
        let counter =
            create_counter_account(wallet.id(), faucet.id(), 0).expect("counter should build");

        let active = counter
            .storage()
            .get_item(FeePolicyManager::active_fee_policy_slot())
            .expect("the active fee policy slot should exist");
        assert_eq!(
            active,
            BasicConstantFeePolicy::root().as_word(),
            "the basic constant fee policy must be the active policy"
        );

        let fee_asset = counter
            .storage()
            .get_item(FeePolicyManager::fee_asset_id_slot())
            .expect("the fee asset slot should exist");
        assert_eq!(
            fee_asset,
            AssetId::new_fungible(faucet.id()).to_word(),
            "fees must be charged in the seeded faucet's asset"
        );
    }

    /// Genesis loads `faucet.mac` through `native_faucet`, which validates it is a fungible faucet
    /// and then bumps its nonce to one itself. A faucet seeded as already-deployed would be
    /// rejected by that path.
    #[test]
    fn fee_faucet_is_a_fungible_faucet_awaiting_deployment() {
        let (faucet, _secret_key) = create_fee_faucet_account().expect("faucet should build");

        assert_eq!(
            faucet.nonce(),
            Felt::ZERO,
            "genesis bumps the nonce when it commits the faucet"
        );
        // The exact check `NativeFaucetConfig::build_account` runs on a file-loaded faucet.
        FungibleFaucet::try_from(&faucet)
            .expect("the seeded faucet must satisfy the genesis native-faucet check");
    }
}
