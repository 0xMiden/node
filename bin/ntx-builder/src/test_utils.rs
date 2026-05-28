//! Shared test helpers for the NTX builder crate.

use miden_protocol::Word;
use miden_protocol::account::{Account, AccountComponent, AccountId, AccountType};
use miden_protocol::block::BlockNumber;
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
    AccountIdBuilder,
};
use miden_protocol::transaction::TransactionId;
use miden_standards::note::{AccountTargetNetworkNote, NetworkAccountTarget, NoteExecutionHint};
use miden_standards::testing::note::NoteBuilder;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;

/// Creates a network account ID from a test constant.
pub fn mock_network_account_id() -> AccountId {
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE.try_into().unwrap()
}

/// Creates a distinct [`TransactionId`] from a seed, for landing-detection tests.
pub fn mock_transaction_id(seed: u32) -> TransactionId {
    TransactionId::from_raw(Word::from([seed, 0, 0, 0]))
}

/// Creates a distinct network account ID using a seeded RNG.
pub fn mock_network_account_id_seeded(seed: u8) -> AccountId {
    AccountIdBuilder::new()
        .account_type(AccountType::Public)
        .build_with_seed([seed; 32])
}

/// Creates a `AccountTargetNetworkNote` targeting the given network account.
pub fn mock_single_target_note(
    network_account_id: AccountId,
    seed: u8,
) -> AccountTargetNetworkNote {
    mock_single_target_note_with_code(network_account_id, seed, None)
}

/// Creates a `AccountTargetNetworkNote` with optional custom note script code.
pub fn mock_single_target_note_with_code(
    network_account_id: AccountId,
    seed: u8,
    code: Option<&str>,
) -> AccountTargetNetworkNote {
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let sender = AccountIdBuilder::new()
        .account_type(AccountType::Private)
        .build_with_rng(&mut rng);

    let target = NetworkAccountTarget::new(network_account_id, NoteExecutionHint::Always)
        .expect("network account should be valid target");

    let mut builder = NoteBuilder::new(sender, rng).attachment(target);
    if let Some(code) = code {
        builder = builder.code(code);
    }

    let note = builder.build().unwrap();

    AccountTargetNetworkNote::try_from(note).expect("note should be single-target network note")
}

/// Creates a mock `Account` for a network account.
///
/// Uses `AccountBuilder` with minimal components needed for serialization.
pub fn mock_account(_account_id: AccountId) -> miden_protocol::account::Account {
    use miden_protocol::account::AccountBuilder;
    use miden_protocol::testing::noop_auth_component::NoopAuthComponent;
    use miden_standards::testing::account_component::MockAccountComponent;

    AccountBuilder::new([0u8; 32])
        .account_type(AccountType::Public)
        .with_component(MockAccountComponent::with_slots(vec![]))
        .with_auth_component(NoopAuthComponent)
        .build_existing()
        .unwrap()
}

/// Creates a mock network [`Account`] with the provided auth component.
pub fn mock_account_with_auth_component(auth_component: impl Into<AccountComponent>) -> Account {
    use miden_protocol::account::AccountBuilder;
    use miden_standards::testing::account_component::MockAccountComponent;

    AccountBuilder::new([0u8; 32])
        .account_type(AccountType::Public)
        .with_component(MockAccountComponent::with_slots(vec![]))
        .with_auth_component(auth_component)
        .build_existing()
        .unwrap()
}

/// Creates a mock `BlockHeader` for the given block number.
pub fn mock_block_header(block_num: BlockNumber) -> miden_protocol::block::BlockHeader {
    miden_protocol::block::BlockHeader::mock(block_num, None, None, &[], Word::default())
}
