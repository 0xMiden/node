//! Shared test helpers for the NTX builder crate.

use miden_node_proto::domain::account::NetworkAccountId;
use miden_protocol::Word;
use miden_protocol::account::{AccountId, AccountStorageMode, AccountType};
use miden_protocol::block::{BlockBody, BlockNumber, SignedBlock};
use miden_protocol::note::Nullifier;
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_REGULAR_NETWORK_ACCOUNT_IMMUTABLE_CODE,
    AccountIdBuilder,
};
use miden_protocol::testing::random_secret_key::random_secret_key;
use miden_protocol::transaction::{OrderedTransactionHeaders, OutputNote, PublicOutputNote};
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

/// Creates a mock [`SignedBlock`] for the given block number containing the provided network notes
/// and nullifiers.
///
/// The block is built with `SignedBlock::new_unchecked`, so the signature is generated against an
/// independent key (not the validator key in the mock header). Suitable for code paths that only
/// observe the block via [`crate::committed_block::CommittedBlockEffects::from_signed_block`].
pub fn mock_signed_block(
    block_num: BlockNumber,
    network_notes: &[AccountTargetNetworkNote],
    nullifiers: Vec<Nullifier>,
) -> SignedBlock {
    let header = mock_block_header(block_num);

    let output_notes: Vec<(usize, OutputNote)> = network_notes
        .iter()
        .enumerate()
        .map(|(idx, note)| {
            let public = PublicOutputNote::new(note.as_note().clone())
                .expect("network note should be public");
            (idx, OutputNote::Public(public))
        })
        .collect();

    let output_note_batches = if output_notes.is_empty() {
        Vec::new()
    } else {
        vec![output_notes]
    };

    let body = BlockBody::new_unchecked(
        Vec::new(),
        output_note_batches,
        nullifiers,
        OrderedTransactionHeaders::new_unchecked(Vec::new()),
    );

    let signature = random_secret_key().sign(header.commitment());

    SignedBlock::new_unchecked(header, body, signature)
}
