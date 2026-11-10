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
#[cfg(test)]
use miden_protocol::block::code_tree::CodeTree;
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
use miden_protocol::transaction::InputNoteCommitment;
use miden_standards::account::wallets::BasicWallet;
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
        assert_eq!(error.code(), Code::InvalidArgument);
        assert_eq!(error.details(), &[8]);
        assert!(error.message().contains("already exists"), "{}", error.message());
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
        let directory = crate::tests::new_tempdir();
        State::bootstrap(genesis, &directory).await.unwrap();
        let (state, writer, _) = State::for_tests(&directory).await;
        Self { state, writer, account, genesis: header }
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
        let logs = miden_protocol::transaction::TransactionLogs::default();
        let log_details =
            miden_protocol::transaction::TransactionLogDetails::Private(logs.commitment());
        ProvenTransaction::new(
            update,
            nullifiers.iter().map(|n| InputNoteCommitment::from_parts_unchecked(*n, None)),
            Vec::<OutputNote>::new(),
            BlockNumber::GENESIS,
            self.genesis.commitment(),
            expiration.into(),
            dummy_execution_proof(),
            log_details,
            miden_protocol::block::code_tree::CodePatch::default(),
        )
        .unwrap()
    }

    async fn commit_block(&mut self, nullifiers: &[Nullifier]) {
        let block_num = self.genesis.block_num().child();
        let tree = NullifierTree::with_entries(nullifiers.iter().map(|n| (*n, block_num))).unwrap();
        let body = BlockBody::new(vec![], vec![], nullifiers.to_vec(), Vec::new()).unwrap();
        let mut mmr = Mmr::new();
        mmr.add(self.genesis.commitment()).unwrap();
        let header = BlockHeader::new(
            self.genesis.commitment(),
            block_num,
            mmr.peaks().hash_peaks(),
            self.genesis.account_root(),
            tree.root(),
            CodeTree::<miden_protocol::crypto::merkle::smt::Smt>::default().root(),
            body.compute_block_note_tree().root(),
            body.compute_transactions_commitment(),
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

#[tokio::test]
async fn decorator_stripping_preserves_logs_and_code_patch() {
    use miden_protocol::block::code_tree::CodePatch;
    use miden_protocol::code::ProcedureRoot;
    use miden_protocol::transaction::TransactionLogDetails;
    let fixture = Fixture::new().await;
    let base = fixture.transaction(fixture.account.id(), &[], 2);
    let package = miden_protocol::testing::assembler::assemble_test_package(
        "rpc-code-patch",
        "test::rpc_patch",
        "pub proc entry push.1 drop end",
    );
    let mast = package.mast_forest().clone();
    let patch = CodePatch::new(
        mast.procedure_digests().map(ProcedureRoot::from_raw).collect(),
        vec![],
        mast,
    )
    .unwrap();
    let public_account = AccountBuilder::new([9; 32])
        .account_type(AccountType::Public)
        .with_component(BasicWallet)
        .with_component(NoopAuthComponent)
        .build_existing()
        .unwrap();
    let account_patch =
        miden_protocol::account::AccountPatch::try_from(public_account.clone()).unwrap();
    let public_update = TxAccountUpdate::new(
        public_account.id(),
        Word::empty(),
        public_account.to_commitment(),
        account_patch.to_commitment(),
        AccountUpdateDetails::Public(account_patch),
    )
    .unwrap();
    for update in [base.account_update().clone(), public_update] {
        use miden_protocol::transaction::{LogTopic, TransactionLog, TransactionLogs};
        let logs = TransactionLogs::new(vec![
            TransactionLog::new(
                update.account_id(),
                LogTopic::from_name("rpc-log-test"),
                vec![Word::from([37_u32; 4])],
            )
            .unwrap(),
        ])
        .unwrap();
        let details = if update.account_id().is_public() {
            TransactionLogDetails::Public(logs)
        } else {
            TransactionLogDetails::Private(logs.commitment())
        };
        let tx = ProvenTransaction::new(
            update,
            base.input_notes().iter().cloned(),
            base.output_notes().iter().cloned(),
            base.ref_block_num(),
            base.ref_block_commitment(),
            base.expiration_block_num(),
            base.proof().clone(),
            details,
            patch.clone(),
        )
        .unwrap();
        let forwarded = strip_transaction_decorators(&tx).unwrap();
        assert_eq!(forwarded.id(), tx.id());
        assert_eq!(forwarded.log_details(), tx.log_details());
        assert_eq!(forwarded.code_patch(), tx.code_patch());
    }
}
