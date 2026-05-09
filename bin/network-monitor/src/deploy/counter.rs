//! Counter program account creation functionality.

use std::path::Path;

use anyhow::Result;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountFile,
    AccountId,
    AccountStorageMode,
    AccountType,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::assembly::Library;
use miden_protocol::utils::serde::Deserializable;
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};
use miden_standards::testing::account_component::IncrNonceAuthComponent;
use tracing::instrument;

use crate::COMPONENT;

pub static OWNER_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::monitor::counter_contract::owner")
        .expect("storage slot name should be valid")
});

pub static COUNTER_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::monitor::counter_contract::counter")
        .expect("storage slot name should be valid")
});

static COUNTER_PROGRAM_LIBRARY: LazyLock<Library> = LazyLock::new(|| {
    let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/counter_program.masl"));
    Library::read_from_bytes(bytes).expect("counter program library should be valid")
});

/// An [`AccountComponent`] implementing the counter contract used by the network monitor.
pub struct CounterComponent {
    pub owner_account_id: AccountId,
}

impl From<CounterComponent> for AccountComponent {
    fn from(component: CounterComponent) -> Self {
        let owner_account_id_prefix = component.owner_account_id.prefix().as_felt();
        let owner_account_id_suffix = component.owner_account_id.suffix();

        let owner_id_slot = StorageSlot::with_value(
            OWNER_SLOT_NAME.clone(),
            Word::from([owner_account_id_suffix, owner_account_id_prefix, Felt::ZERO, Felt::ZERO]),
        );

        let counter_slot = StorageSlot::with_value(COUNTER_SLOT_NAME.clone(), Word::empty());

        let metadata = AccountComponentMetadata::new("counter::program", AccountType::all());

        AccountComponent::new(
            COUNTER_PROGRAM_LIBRARY.clone(),
            vec![counter_slot, owner_id_slot],
            metadata,
        )
        .expect("counter component should be valid")
    }
}

/// Create a counter program account.
#[instrument(target = COMPONENT, name = "create-counter-account", skip_all, ret(level = "debug"))]
pub fn create_counter_account(owner_account_id: AccountId) -> Result<Account> {
    let counter_component: AccountComponent = CounterComponent { owner_account_id }.into();
    let incr_nonce_auth: AccountComponent = IncrNonceAuthComponent.into();

    let init_seed: [u8; 32] = rand::random();
    let counter_account = AccountBuilder::new(init_seed)
        .account_type(AccountType::RegularAccountUpdatableCode)
        .storage_mode(AccountStorageMode::Network)
        .with_component(counter_component)
        .with_auth_component(incr_nonce_auth)
        .build()?;

    Ok(counter_account)
}

/// Save counter program account to disk without extra auth material.
pub fn save_counter_account(account: &Account, file_path: &Path) -> Result<()> {
    let account_file = AccountFile::new(account.clone(), vec![]);
    account_file.write(file_path)?;
    Ok(())
}
