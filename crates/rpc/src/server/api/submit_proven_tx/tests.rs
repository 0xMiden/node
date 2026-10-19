use std::sync::Arc;

use miden_node_store::GenesisState;
use miden_node_store::state::BlockWriter;
use miden_node_utils::fee::{test_fee_params, test_protocol_config};
use miden_protocol::Word;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountId,
    AccountType,
    AccountUpdateDetails,
};
use miden_protocol::block::nullifier_tree::NullifierTree;
use miden_protocol::block::{
    BlockBody,
    BlockHeader,
    BlockNumber,
    BlockSignatures,
    SignedBlock,
    ValidatorConfig,
};
use miden_protocol::crypto::merkle::mmr::Mmr;
use miden_protocol::note::Nullifier;
use miden_protocol::testing::dummy_execution_proof;
use miden_protocol::testing::noop_auth_component::NoopAuthComponent;
use miden_protocol::testing::random_secret_key::random_secret_key;
use miden_protocol::transaction::{InputNoteCommitment, OrderedTransactionHeaders};
use miden_standards::account::wallets::BasicWallet;
use tempfile::TempDir;
use tonic::Code;

use super::*;

#[tokio::test(flavor = "multi_thread")]
async fn forwarding_checks_expiration_at_the_committed_tip() {
    let mut fixture = Fixture::new().await;
    fixture.commit_block(&[]).await;

    let expired = fixture.transaction(fixture.account.id(), &[], 1);
    let error = check_nullifiers_and_expiration(&fixture.state, expired).await.unwrap_err();
    assert_eq!(error.code(), Code::InvalidArgument);
    assert_eq!(error.details(), &[1]);

    let live = fixture.transaction(fixture.account.id(), &[], 2);
    check_nullifiers_and_expiration(&fixture.state, live).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn forwarding_rejects_committed_nullifiers_with_the_submission_error_code() {
    let mut fixture = Fixture::new().await;
    let nullifier = Nullifier::from_raw(Word::from([1_u32, 2, 3, 4]));
    let tx = fixture.transaction(fixture.account.id(), &[nullifier], 2);
    check_nullifiers_and_expiration(&fixture.state, tx.clone()).await.unwrap();

    fixture.commit_block(&[nullifier]).await;
    let error = check_nullifiers_and_expiration(&fixture.state, tx).await.unwrap_err();
    assert_eq!(error.code(), Code::InvalidArgument);
    assert_eq!(error.details(), &[8]);
    assert!(error.message().contains("nullifiers already exist"));
}

#[tokio::test(flavor = "multi_thread")]
async fn forwarding_rejects_new_accounts_with_an_existing_prefix() {
    let fixture = Fixture::new().await;
    let mut id: [u8; 15] = fixture.account.id().into();
    id[14] ^= 1;
    let colliding_id = AccountId::try_from(id).unwrap();
    assert_ne!(colliding_id, fixture.account.id());
    assert_eq!(colliding_id.prefix(), fixture.account.id().prefix());

    let nullifier = Nullifier::from_raw(Word::from([1_u32, 2, 3, 4]));
    for nullifiers in [vec![], vec![nullifier]] {
        let tx = fixture.transaction(colliding_id, &nullifiers, 2);
        let error = check_nullifiers_and_expiration(&fixture.state, tx).await.unwrap_err();
        assert_eq!(error.code(), Code::Internal);
        assert_eq!(error.details(), &[0]);
    }

    id[0] ^= 1;
    let unique_id = AccountId::try_from(id).unwrap();
    let tx = fixture.transaction(unique_id, &[nullifier], 2);
    check_nullifiers_and_expiration(&fixture.state, tx).await.unwrap();
}

/// A store with one private wallet and support for committing its first block.
struct Fixture {
    state: Arc<State>,
    writer: BlockWriter,
    account: Account,
    genesis: BlockHeader,
    _directory: TempDir,
}

impl Fixture {
    async fn new() -> Self {
        let account = AccountBuilder::new([7; 32])
            .account_type(AccountType::Private)
            .with_component(BasicWallet)
            .with_component(NoopAuthComponent)
            .build_existing()
            .unwrap();
        let genesis = GenesisState::new(
            vec![account.clone()],
            test_fee_params(),
            1,
            ValidatorConfig::new(vec![random_secret_key().public_key()], 1).unwrap(),
            test_protocol_config(),
        )
        .into_block()
        .unwrap();
        let header = genesis.inner().header().clone();
        let directory = tempfile::tempdir().unwrap();
        State::bootstrap(genesis, directory.path()).await.unwrap();
        let (state, writer, _) = State::for_tests(directory.path()).await;
        Self {
            state,
            writer,
            account,
            genesis: header,
            _directory: directory,
        }
    }

    /// Builds transaction inputs for store validation; proof verification happens before this
    /// check.
    fn transaction(
        &self,
        id: AccountId,
        nullifiers: &[Nullifier],
        expiration: u32,
    ) -> ProvenTransaction {
        let initial = if id == self.account.id() {
            self.account.to_commitment()
        } else {
            Word::empty()
        };
        let update = TxAccountUpdate::new(
            id,
            initial,
            Word::from([42_u32; 4]),
            Word::empty(),
            AccountUpdateDetails::Private,
        )
        .unwrap();
        ProvenTransaction::new(
            update,
            nullifiers.iter().map(|n| InputNoteCommitment::from_parts_unchecked(*n, None)),
            Vec::<OutputNote>::new(),
            BlockNumber::GENESIS,
            self.genesis.commitment(),
            expiration.into(),
            dummy_execution_proof(),
        )
        .unwrap()
    }

    async fn commit_block(&mut self, nullifiers: &[Nullifier]) {
        let block_num = self.genesis.block_num().child();
        let tree = NullifierTree::with_entries(nullifiers.iter().map(|n| (*n, block_num))).unwrap();
        let body = BlockBody::new(
            vec![],
            vec![],
            nullifiers.to_vec(),
            OrderedTransactionHeaders::new_unchecked(vec![]),
        )
        .unwrap();
        let mut mmr = Mmr::new();
        mmr.add(self.genesis.commitment()).unwrap();
        let header = BlockHeader::new(
            self.genesis.commitment(),
            block_num,
            mmr.peaks().hash_peaks(),
            self.genesis.account_root(),
            tree.root(),
            body.compute_block_note_tree().root(),
            body.transaction_commitment(),
            self.genesis.validator_config().clone(),
            self.genesis.fee_parameters().clone(),
            self.genesis.protocol_config_commitment(),
            None,
            self.genesis.timestamp() + 1,
        );
        let block = SignedBlock::new_unchecked(header, body, BlockSignatures::new(vec![]).unwrap());
        self.writer.apply_block(block, None).await.unwrap();
    }
}
