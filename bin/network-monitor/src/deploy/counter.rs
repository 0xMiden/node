//! Counter program account creation functionality.

use std::collections::BTreeSet;

use anyhow::Result;
use miden_node_utils::tracing::miden_instrument;
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
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};
use miden_standards::account::auth::AuthNetworkAccount;
use miden_standards::code_builder::CodeBuilder;

use crate::COMPONENT;
use crate::counter::create_increment_script;

pub static OWNER_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::monitor::counter_contract::owner")
        .expect("storage slot name should be valid")
});

pub static COUNTER_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::monitor::counter_contract::counter")
        .expect("storage slot name should be valid")
});

/// Create a counter program account with custom MASM script.
#[miden_instrument(
    target = COMPONENT,
    name = "create-counter-account",
    skip_all,
    ret(level = "debug"),
)]
pub fn create_counter_account(owner_account_id: AccountId) -> Result<Account> {
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

    let mut allowed_scripts = BTreeSet::new();

    let increment_script = create_increment_script().expect("is valid note script");

    allowed_scripts.insert(increment_script.root());

    // TODO(https://github.com/0xMiden/protocol/issues/3050): once the ntx-builder re-enables the
    // expiration tx script, this account must also allowlist that script's root via
    // `.with_allowed_tx_scripts([..])`, or its network transactions will be rejected by the
    // tx-script allowlist. This waits on the canonical, frozen expiration script (#3050) so the
    // root can be pinned here without duplicating the ntx-builder's script/delta.
    let network_account_auth: AccountComponent =
        AuthNetworkAccount::with_allowed_notes(allowed_scripts)
            .expect("list is not empty")
            .into();

    // Create the counter program account
    let init_seed: [u8; 32] = rand::random();
    let counter_account = AccountBuilder::new(init_seed)
        .account_type(AccountType::Public)
        .with_component(account_code)
        .with_auth_component(network_account_auth)
        .build()?;

    Ok(counter_account)
}
