//! Counter program account creation functionality.

use std::collections::BTreeSet;

use anyhow::Result;
use miden_node_tracing::miden_instrument;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountId,
    AccountType,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::asset::AssetAmount;
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};
use miden_standards::account::auth::AuthNetworkAccount;
use miden_standards::account::fees::{BasicConstantFeePolicy, FeePolicyManager};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::note::{FeeSponsorshipNote, P2idNote};
use miden_standards::tx_script::{ExpirationTransactionScript, SendWalletNotesTransactionScript};

use crate::COMPONENT;
use crate::counter::create_increment_script;
use crate::funding::max_fee_per_transaction;

pub static OWNER_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::monitor::counter_contract::owner")
        .expect("storage slot name should be valid")
});

pub static COUNTER_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::monitor::counter_contract::counter")
        .expect("storage slot name should be valid")
});

/// Create a counter program account with custom MASM script.
///
/// The account has the same shape on every chain:
///
/// - it prices the increment note at the per-transaction fee bound, so on a fee-charging chain
///   each increment attaches a `FEE_SPONSORSHIP` note paying for the network transaction that
///   consumes it (on a zero-fee chain the bound is zero and no sponsorship is attached);
/// - it allowlists (at zero price) the `FEE_SPONSORSHIP` note and the P2ID note funding its
///   creation fee;
/// - it carries `BasicWallet`, since the P2ID script claims assets via `receive_asset`.
#[miden_instrument(
    target = COMPONENT,
    name = "create-counter-account",
    ret(level = "debug"),
)]
pub fn create_counter_account(
    owner_account_id: AccountId,
    fee_faucet_id: AccountId,
    verification_base_fee: u32,
) -> Result<Account> {
    // Load and customize the MASM script
    let script =
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/assets/counter_program.masm"));

    // Compile the account code
    let owner_account_id_prefix = owner_account_id.prefix().as_felt();
    let owner_account_id_suffix = owner_account_id.suffix();

    let owner_id_slot = StorageSlot::with_value(
        OWNER_SLOT_NAME.clone(),
        Word::from([owner_account_id_suffix, owner_account_id_prefix, Felt::ZERO, Felt::ZERO]),
    );

    let counter_slot = StorageSlot::with_value(COUNTER_SLOT_NAME.clone(), Word::empty());

    let component_code =
        CodeBuilder::default().compile_component_code("counter::program", script)?;

    let metadata = AccountComponentMetadata::new("counter::program");
    let account_code =
        AccountComponent::new(component_code, vec![counter_slot, owner_id_slot], metadata)?;

    let increment_script = create_increment_script().expect("is valid note script");

    // The account's auth procedure prices every note it consumes, and any transaction creating a
    // note targeted at it prices that note through the same policy via FPI. Every allowlisted note
    // script must have a schedule entry, since a script without one aborts fee estimation. The
    // allowlist is derived from the schedule to keep the two aligned by construction.
    let increment_note_fee = AssetAmount::new(max_fee_per_transaction(verification_base_fee))
        .expect("the per-transaction fee bound fits an asset amount");
    let fee_schedule = [
        (increment_script.root(), increment_note_fee),
        (FeeSponsorshipNote::script_root(), AssetAmount::ZERO),
        (P2idNote::script_root(), AssetAmount::ZERO),
    ];
    let allowed_scripts = BTreeSet::from(fee_schedule.map(|(root, _)| root));

    let fee_policy = BasicConstantFeePolicy::new().with_fees(fee_schedule).into();
    let fee_policy_manager = FeePolicyManager::builder()
        .fee_faucet_id(fee_faucet_id)
        .active_fee_policy(fee_policy)
        .build();

    let auth_component = AuthNetworkAccount::custom(allowed_scripts, fee_policy_manager)?
        .with_allowed_tx_scripts([
            ExpirationTransactionScript::script_root(),
            SendWalletNotesTransactionScript::script_root(),
        ]);

    let init_seed: [u8; 32] = rand::random();
    let counter_account = AccountBuilder::new(init_seed)
        .account_type(AccountType::Public)
        .with_components(auth_component)
        .with_component(account_code)
        .with_component(BasicWallet)
        .build()?;

    Ok(counter_account)
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::account::StorageMapKey;
    use miden_protocol::asset::{AssetId, FungibleAsset};
    use miden_standards::account::auth::NetworkAccount;
    use miden_standards::note::FeeSponsorshipNote;

    use super::*;
    use crate::deploy::wallet::create_wallet_account;

    /// The note allowlist and the fee schedule must have exactly the expected shape.
    ///
    /// The exact-set comparison pins the allowlist on both sides: the three notes the counter can
    /// service must be present, and the `NETWORK_ACCOUNT_CONFIG` note that
    /// `AuthNetworkAccount::new` would allowlist by default must stay out, since it needs an
    /// `Authority` component the counter does not have and anyone could send one whose consumption
    /// aborts in `assert_authorized`.
    ///
    /// The schedule is checked directly because `NetworkAccount::new` does not look at fee-policy
    /// storage at all: without these assertions the fee wiring could be deleted whole and every
    /// other test would stay green while the live FPI aborted fee estimation.
    #[test]
    fn allowlist_and_fee_schedule_have_the_expected_shape() {
        const BASE_FEE: u32 = 500;
        let (wallet, _secret_key) = create_wallet_account().expect("wallet account should build");
        let fee_faucet_id = FungibleAsset::mock_issuer();
        let counter = create_counter_account(wallet.id(), fee_faucet_id, BASE_FEE)
            .expect("counter account should build");

        let network_account = NetworkAccount::new(counter.clone())
            .expect("counter should be a valid network account");
        let allowlisted = network_account.allowed_notes().allowed_script_roots();
        let increment_root = create_increment_script().expect("is valid note script").root();
        let expected: BTreeSet<_> =
            [increment_root, FeeSponsorshipNote::script_root(), P2idNote::script_root()].into();
        assert_eq!(
            allowlisted, &expected,
            "exactly the increment, sponsorship, and P2ID notes must be allowlisted"
        );

        // A scheduled entry is `[fee_amount, 0, 0, 1]`: the trailing set-marker is what
        // distinguishes an explicit zero fee from an absent key, since storage maps prune zero
        // words and return the zero word for anything unset.
        let schedule_entry = |root: miden_protocol::note::NoteScriptRoot| {
            counter
                .storage()
                .get_map_item(
                    BasicConstantFeePolicy::fee_schedule_slot_name(),
                    StorageMapKey::new(root.as_word()),
                )
                .expect("the fee schedule slot should be a map")
        };

        let expected_price =
            Felt::new(max_fee_per_transaction(BASE_FEE)).expect("price fits the field");
        assert_eq!(
            schedule_entry(increment_root),
            Word::from([expected_price, Felt::ZERO, Felt::ZERO, Felt::ONE]),
            "the increment note must be priced at the per-transaction fee bound"
        );

        let zero_entry = Word::from([Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::ONE]);
        assert_eq!(schedule_entry(FeeSponsorshipNote::script_root()), zero_entry);
        assert_eq!(schedule_entry(P2idNote::script_root()), zero_entry);

        // Dropping the default allowlist must not cost the account its serviceability: the ntx
        // builder attaches the expiration script to every network transaction, and the store
        // classifies an account whose tx-script allowlist lacks that root as non-network.
        assert!(
            network_account.allows_tx_script(&ExpirationTransactionScript::script_root()),
            "the canonical expiration tx script must stay allowlisted"
        );
        assert!(
            network_account.allows_tx_script(&SendWalletNotesTransactionScript::script_root()),
            "the canonical wallet send-notes tx script must stay allowlisted"
        );
    }

    /// The fee policy must be the *active* one and denominated in the faucet passed in, otherwise
    /// fee estimation dispatches nowhere or charges the wrong asset.
    #[test]
    fn fee_policy_is_active_and_uses_the_given_faucet() {
        let (wallet, _secret_key) = create_wallet_account().expect("wallet account should build");
        let fee_faucet_id = FungibleAsset::mock_issuer();
        let counter = create_counter_account(wallet.id(), fee_faucet_id, 0)
            .expect("counter account should build");

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
            AssetId::new_fungible(fee_faucet_id).to_word(),
            "fees must be charged in the fee faucet's asset"
        );
    }
}
