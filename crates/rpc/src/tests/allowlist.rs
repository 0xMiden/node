use std::collections::BTreeMap;

use miden_node_proto::generated::transaction::SealedTransactionInputs;
use miden_protocol::batch::{ProposedBatch, ProvenBatch};
use miden_protocol::crypto::merkle::mmr::PartialMmr;
use miden_protocol::transaction::PartialBlockchain;
use miden_standards::account::auth::NetworkAccount;
use miden_standards::account::fees::{BasicConstantFeePolicy, FeePolicyManager};

use super::*;

impl TestStore {
    fn account_transaction(&self, account: &Account, is_new: bool) -> ProvenTransaction {
        let patch = AccountPatch::try_from(account.clone()).unwrap();
        let details = if account.is_public() {
            AccountUpdateDetails::Public(patch.clone())
        } else {
            AccountUpdateDetails::Private
        };
        let update = TxAccountUpdate::new(
            account.id(),
            if is_new {
                Word::empty()
            } else {
                Word::from([1u32, 2, 3, 4])
            },
            account.to_commitment(),
            patch.to_commitment(),
            details,
        )
        .unwrap();
        ProvenTransaction::new(
            update,
            Vec::<miden_protocol::transaction::InputNoteCommitment>::new(),
            Vec::<OutputNote>::new(),
            0.into(),
            self.genesis_commitment(),
            u32::MAX.into(),
            ExecutionProof::new_dummy(),
        )
        .unwrap()
    }
}

#[tokio::test]
async fn account_admission_only_restricts_new_non_network_accounts() {
    let store = TestStore::start().await;
    let allowlist = store.bootstrap_allowlist();
    let admission = AccountAdmission::enabled(Arc::clone(&allowlist));
    let disabled = AccountAdmission::disabled(Arc::clone(&allowlist));

    for account_type in [AccountType::Public, AccountType::Private] {
        let account = AccountBuilder::new([1; 32])
            .account_type(account_type)
            .with_component(BasicWallet)
            .with_component(NoopAuthComponent)
            .build_existing()
            .unwrap();
        let creation = store.account_transaction(&account, true);
        let existing = store.account_transaction(&account, false);

        let error = admission.check(creation.account_update()).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);
        admission.check(existing.account_update()).await.unwrap();
        disabled.check(creation.account_update()).await.unwrap();
        assert!(!allowlist.contains_account(creation.account_id()).await.unwrap());

        allowlist.add_account(creation.account_id()).await.unwrap();
        admission.check(creation.account_update()).await.unwrap();
    }

    let network_account = NetworkAccount::builder(
        [2; 32],
        [miden_protocol::note::NoteScriptRoot::from_array([1, 2, 3, 4])].into(),
        FeePolicyManager::builder()
            .fee_faucet_id(FungibleAsset::mock_issuer())
            .active_fee_policy(BasicConstantFeePolicy::new().into())
            .build(),
    )
    .unwrap()
    .with_component(BasicWallet)
    .build_existing()
    .unwrap();
    let creation = store.account_transaction(&network_account, true);
    admission.check(creation.account_update()).await.unwrap();
    assert!(!allowlist.contains_account(creation.account_id()).await.unwrap());
}

#[tokio::test]
async fn submission_endpoints_reject_unregistered_creation_without_partial_batch_admission() {
    let store = TestStore::start().await;
    let allowlist = store.bootstrap_allowlist();
    let admission = AccountAdmission::enabled(Arc::clone(&allowlist));
    let guard = TestServerGuard(CancellationToken::new());
    let block_producer = BlockProducerApi::new(
        Arc::clone(&store.state),
        0.into(),
        BlockProducerApiConfig::default(),
        guard.0.clone(),
    );
    let public = RpcService::new(
        Arc::clone(&store.state),
        RpcBackend::sequencer(
            block_producer.clone(),
            ValidatorClients::new(vec![dummy_client::<ValidatorClient>()]).unwrap(),
            admission.clone(),
        ),
        None,
        NonZeroUsize::new(10).unwrap(),
        None,
    );
    let internal = SequencerInternalService {
        state: Arc::clone(&store.state),
        block_producer,
        account_admission: admission,
    };

    let transactions = [3, 4].map(|seed| {
        let (account, _) = build_test_account([seed; 32]);
        Arc::new(store.account_transaction(&account, true))
    });
    allowlist.add_account(transactions[0].account_id()).await.unwrap();

    let header = store
        .state
        .view()
        .get_block_header(Some(0.into()), false)
        .await
        .unwrap()
        .0
        .unwrap();
    let batch = ProposedBatch::new_unverified(
        transactions.to_vec(),
        header.clone(),
        PartialBlockchain::new(PartialMmr::default(), []).unwrap(),
        BTreeMap::new(),
    )
    .unwrap();
    let proven_batch = ProvenBatch::new_unchecked(
        batch.id(),
        header.commitment(),
        header.block_num(),
        batch.account_updates().clone(),
        batch.input_notes().clone(),
        batch.output_notes().to_vec(),
        batch.batch_expiration_block_num(),
        batch.transaction_headers(),
        ExecutionProof::new_dummy(),
    )
    .unwrap();
    let tx = proto::sequencer::AuthenticatedTransaction {
        transaction: transactions[1].to_bytes(),
        ..Default::default()
    };
    let authenticated_batch = proto::sequencer::AuthenticatedTransactionBatch {
        proposed_batch: batch.to_bytes(),
        auth_inputs: transactions
            .iter()
            .map(|tx| proto::sequencer::AuthInputs {
                account_id: Some(tx.account_id().into()),
                ..Default::default()
            })
            .collect(),
    };

    for result in [
        public
            .submit_proven_tx(Request::new(proto::transaction::ProvenTransaction {
                transaction: transactions[1].to_bytes(),
                sealed_transaction_inputs: None,
            }))
            .await,
        public
            .submit_proven_tx_batch(Request::new(proto::transaction::TransactionBatch {
                batch_proof: proven_batch.to_bytes(),
                proposed_batch: Some(batch.to_bytes()),
                sealed_transaction_inputs: vec![SealedTransactionInputs::default(); 2],
            }))
            .await,
        internal.submit_authenticated_tx(Request::new(tx)).await,
        internal
            .submit_authenticated_tx_batch(Request::new(authenticated_batch.clone()))
            .await,
    ] {
        let status = result.unwrap_err();
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
        assert!(status.message().contains(&transactions[1].account_id().to_string()));
    }

    // The retry must not conflict with a partially admitted transaction from the rejected batch.
    allowlist.add_account(transactions[1].account_id()).await.unwrap();
    internal
        .submit_authenticated_tx_batch(Request::new(authenticated_batch))
        .await
        .unwrap();
}
