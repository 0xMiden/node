//! Shared test helpers for the NTX builder crate.

use miden_protocol::Word;
use miden_protocol::account::{Account, AccountComponent, AccountId, AccountType};
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{NoteId, NoteScriptRoot};
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

/// Creates a `AccountTargetNetworkNote` carrying the given execution hint.
pub fn mock_single_target_note_with_hint(
    network_account_id: AccountId,
    seed: u8,
    hint: NoteExecutionHint,
) -> AccountTargetNetworkNote {
    mock_single_target_note_inner(network_account_id, seed, None, hint)
}

/// Creates a `AccountTargetNetworkNote` with optional custom note script code.
pub fn mock_single_target_note_with_code(
    network_account_id: AccountId,
    seed: u8,
    code: Option<&str>,
) -> AccountTargetNetworkNote {
    mock_single_target_note_inner(network_account_id, seed, code, NoteExecutionHint::Always)
}

fn mock_single_target_note_inner(
    network_account_id: AccountId,
    seed: u8,
    code: Option<&str>,
    hint: NoteExecutionHint,
) -> AccountTargetNetworkNote {
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let sender = AccountIdBuilder::new()
        .account_type(AccountType::Private)
        .build_with_rng(&mut rng);

    let target = NetworkAccountTarget::new(network_account_id, hint)
        .expect("network account should be valid target");

    let mut builder = NoteBuilder::new(sender, rng).attachment(target);
    if let Some(code) = code {
        builder = builder.code(code);
    }

    let note = builder.build().unwrap();

    AccountTargetNetworkNote::try_from(note).expect("note should be single-target network note")
}

/// Creates a `FEE_SPONSORSHIP` [`Note`](miden_protocol::note::Note) sponsoring `feature_note_id`,
/// tagged for `target_account_id`. Reclaim is left disabled.
pub fn mock_sponsorship_note(
    target_account_id: AccountId,
    feature_note_id: NoteId,
    seed: u8,
) -> miden_protocol::note::Note {
    mock_sponsorship_note_with_amount(target_account_id, feature_note_id, seed, 100)
}

/// Creates a `FEE_SPONSORSHIP` note carrying `amount` units of its fungible fee asset.
pub fn mock_sponsorship_note_with_amount(
    target_account_id: AccountId,
    feature_note_id: NoteId,
    seed: u8,
    amount: u64,
) -> miden_protocol::note::Note {
    use miden_protocol::asset::FungibleAsset;

    mock_sponsorship_note_with_faucet_and_amount(
        target_account_id,
        feature_note_id,
        seed,
        FungibleAsset::mock_issuer(),
        amount,
    )
}

/// Creates a `FEE_SPONSORSHIP` note carrying `amount` units issued by `fee_faucet_id`.
pub fn mock_sponsorship_note_with_faucet_and_amount(
    target_account_id: AccountId,
    feature_note_id: NoteId,
    seed: u8,
    fee_faucet_id: AccountId,
    amount: u64,
) -> miden_protocol::note::Note {
    use miden_protocol::asset::FungibleAsset;
    use miden_standards::note::FeeSponsorshipNote;

    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let sender = AccountIdBuilder::new()
        .account_type(AccountType::Private)
        .build_with_rng(&mut rng);
    let asset =
        FungibleAsset::new(fee_faucet_id, amount).expect("mock fungible asset should be valid");

    FeeSponsorshipNote::builder()
        .sender(sender)
        .target_account(target_account_id)
        .feature_note_id(feature_note_id)
        .asset(asset)
        .serial_number(Word::from([u32::from(seed), 0, 0, 1]))
        .build()
        .expect("sponsorship note should build for a public target")
        .into()
}

/// Creates a decoded [`SponsorshipNote`](crate::sponsorship::SponsorshipNote) sponsoring
/// `feature_note_id`, tagged for `target_account_id`.
pub fn mock_sponsorship(
    target_account_id: AccountId,
    feature_note_id: miden_protocol::note::NoteId,
    seed: u8,
) -> crate::sponsorship::SponsorshipNote {
    let note = mock_sponsorship_note(target_account_id, feature_note_id, seed);
    crate::sponsorship::SponsorshipNote::try_from(note).expect("mock sponsorship note must decode")
}

/// Creates a decoded sponsorship carrying `amount` units of its fungible fee asset.
pub fn mock_sponsorship_with_amount(
    target_account_id: AccountId,
    feature_note_id: miden_protocol::note::NoteId,
    seed: u8,
    amount: u64,
) -> crate::sponsorship::SponsorshipNote {
    let note = mock_sponsorship_note_with_amount(target_account_id, feature_note_id, seed, amount);
    crate::sponsorship::SponsorshipNote::try_from(note).expect("mock sponsorship note must decode")
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
        .with_component(NoopAuthComponent)
        .build_existing()
        .unwrap()
}

/// Creates a mock network [`Account`] with the provided auth components.
pub fn mock_account_with_auth_component(
    auth_components: impl IntoIterator<Item = impl Into<AccountComponent>>,
) -> Account {
    use miden_protocol::account::AccountBuilder;
    use miden_standards::testing::account_component::MockAccountComponent;

    AccountBuilder::new([0u8; 32])
        .account_type(AccountType::Public)
        .with_component(MockAccountComponent::with_slots(vec![]))
        .with_components(auth_components)
        .build_existing()
        .unwrap()
}

/// Creates a mock network [`Account`] whose note-script allowlist contains the given roots.
///
/// The resulting account passes `NetworkAccount::new`, so it is treated as a network account.
pub fn mock_network_account(
    allowed_script_roots: impl IntoIterator<Item = NoteScriptRoot>,
) -> Account {
    use std::collections::BTreeSet;

    use miden_protocol::asset::FungibleAsset;
    use miden_standards::account::auth::AuthNetworkAccount;
    use miden_standards::account::fees::FeePolicyManager;

    mock_account_with_auth_component(
        AuthNetworkAccount::new(
            allowed_script_roots.into_iter().collect::<BTreeSet<_>>(),
            FeePolicyManager::mock(FungibleAsset::mock_issuer()),
        )
        .expect("non-empty allowlist should construct"),
    )
}

/// Creates a mock `BlockHeader` for the given block number.
pub fn mock_block_header(block_num: BlockNumber) -> miden_protocol::block::BlockHeader {
    miden_protocol::block::BlockHeader::mock(block_num, None, None, &[], Word::default())
}

/// Creates a mock genesis [`SignedBlock`] with an empty body.
///
/// Like a real genesis block, it carries no signatures.
pub fn mock_genesis_block() -> miden_protocol::block::SignedBlock {
    use miden_protocol::block::{BlockBody, BlockSignatures, SignedBlock};
    use miden_protocol::transaction::OrderedTransactionHeaders;

    let header = mock_block_header(BlockNumber::GENESIS);
    let body = BlockBody::new_unchecked(
        Vec::new(),
        Vec::new(),
        Vec::new(),
        OrderedTransactionHeaders::new_unchecked(Vec::new()),
    );
    let signatures = BlockSignatures::new(Vec::new()).unwrap();
    SignedBlock::new_unchecked(header, body, signatures)
}

/// Builds a full-state [`AccountUpdateDetails`] for a network account. The returned account passes
/// `NetworkAccount::new`, so the ntx-builder treats the update as a network-account creation.
pub fn mock_network_account_update() -> (Account, miden_protocol::account::AccountUpdateDetails) {
    use miden_protocol::account::{AccountPatch, AccountUpdateDetails};

    // The allowlist content is irrelevant here, any non-empty set yields a valid network account.
    let root = mock_single_target_note(mock_network_account_id(), 1).as_note().script().root();
    let account = mock_network_account([root]);
    let details = AccountUpdateDetails::Public(
        AccountPatch::try_from(account.clone()).expect("full-state patch should build"),
    );
    (account, details)
}

/// Creates a mock genesis [`SignedBlock`] that seeds a single network account and contains no
/// transactions. Returns the block and the seeded account id.
///
/// Like a real genesis block, it carries no signatures.
pub fn mock_genesis_block_with_network_account() -> (miden_protocol::block::SignedBlock, AccountId)
{
    use miden_protocol::block::{BlockAccountUpdate, BlockBody, BlockSignatures, SignedBlock};
    use miden_protocol::transaction::OrderedTransactionHeaders;

    let (account, details) = mock_network_account_update();
    let account_id = account.id();
    let update = BlockAccountUpdate::new(account_id, account.to_commitment(), details);

    let header = mock_block_header(BlockNumber::GENESIS);
    let body = BlockBody::new_unchecked(
        vec![update],
        Vec::new(),
        Vec::new(),
        OrderedTransactionHeaders::new_unchecked(Vec::new()),
    );
    let signatures = BlockSignatures::new(Vec::new()).unwrap();
    (SignedBlock::new_unchecked(header, body, signatures), account_id)
}
