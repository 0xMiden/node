//! Shared test helpers for the NTX builder crate.

use miden_node_proto::domain::account::NetworkAccountId;
use miden_protocol::Word;
use miden_protocol::account::{AccountId, AccountStorageMode, AccountType};
use miden_protocol::block::BlockNumber;
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_REGULAR_NETWORK_ACCOUNT_IMMUTABLE_CODE,
    AccountIdBuilder,
};
use miden_standards::note::{AccountTargetNetworkNote, NetworkAccountTarget, NoteExecutionHint};
use miden_standards::testing::note::NoteBuilder;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;

/// Creates a network account ID from a test constant.
pub fn mock_network_account_id() -> NetworkAccountId {
    let account_id: AccountId =
        ACCOUNT_ID_REGULAR_NETWORK_ACCOUNT_IMMUTABLE_CODE.try_into().unwrap();
    NetworkAccountId::try_from(account_id).unwrap()
}

/// Creates a distinct network account ID using a seeded RNG.
pub fn mock_network_account_id_seeded(seed: u8) -> NetworkAccountId {
    let account_id = AccountIdBuilder::new()
        .account_type(AccountType::RegularAccountImmutableCode)
        .storage_mode(AccountStorageMode::Network)
        .build_with_seed([seed; 32]);
    NetworkAccountId::try_from(account_id).unwrap()
}

/// Creates a `AccountTargetNetworkNote` targeting the given network account.
pub fn mock_single_target_note(
    network_account_id: NetworkAccountId,
    seed: u8,
) -> AccountTargetNetworkNote {
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let sender = AccountIdBuilder::new()
        .account_type(AccountType::RegularAccountImmutableCode)
        .storage_mode(AccountStorageMode::Private)
        .build_with_rng(&mut rng);

    let target = NetworkAccountTarget::new(network_account_id.inner(), NoteExecutionHint::Always)
        .expect("network account should be valid target");

    let note = NoteBuilder::new(sender, rng).attachment(target).build().unwrap();

    AccountTargetNetworkNote::try_from(note).expect("note should be single-target network note")
}

/// Creates a mock `BlockHeader` for the given block number.
pub fn mock_block_header(block_num: BlockNumber) -> miden_protocol::block::BlockHeader {
    miden_protocol::block::BlockHeader::mock(block_num, None, None, &[], Word::default())
}
