use std::collections::BTreeMap;

use miden_protocol::batch::ProposedBatch;
use miden_standards::account::auth::NetworkAccount;
use miden_standards::account::fees::{BasicConstantFeePolicy, FeePolicyManager};

use super::*;

impl TestStore {
    async fn with_account_creation_batch() -> (Self, ProposedBatch) {
        let mut builder = MockChainBuilder::new()
            .fee_faucet_id(FungibleAsset::mock_issuer())
            .verification_base_fee(1);
        let accounts = [
            builder
                .create_new_wallet(Auth::BasicAuth {
                    auth_scheme: AuthScheme::Falcon512Poseidon2,
                })
                .unwrap(),
            builder
                .create_new_wallet(Auth::BasicAuth {
                    auth_scheme: AuthScheme::Falcon512Poseidon2,
                })
                .unwrap(),
        ];
        let notes = accounts.each_ref().map(|account| {
            builder
                .add_p2id_note(
                    account.id(),
                    account.id(),
                    &[FungibleAsset::mock(1_000_000)],
                    NoteType::Private,
                )
                .unwrap()
        });
        let chain = builder.build().unwrap();
        let store =
            Self::start_from_mock_genesis(&chain.latest_block(), chain.protocol_config()).await;
        let mut transactions = Vec::new();
        // Batch decoding verifies each transaction proof before the admission check.
        for (account, note) in accounts.into_iter().zip(notes) {
            let (auth_args, advice) = commit_fee_conversion_info(
                FeeConversionInfo::one_to_one(FungibleAsset::mock_issuer()),
                Word::from([9u32, 10, 11, 12]),
            );
            let context = chain
                .build_transaction(account)
                .authenticated_input_note(note.id())
                .auth_args(auth_args)
                .add_advice_map_entry(auth_args, advice)
                .build()
                .unwrap();
            let executed = Box::pin(context.execute()).await.unwrap();
            let inputs = executed.tx_inputs().clone();
            let proven = spawn_blocking_in_current_span(move || {
                LocalTransactionProver::default().prove(inputs)
            })
            .await
            .unwrap()
            .unwrap();
            transactions.push(Arc::new(proven));
        }
        let batch = ProposedBatch::new(
            transactions,
            chain.latest_block_header(),
            chain.latest_partial_blockchain(),
            BTreeMap::new(),
            miden_protocol::MIN_PROOF_SECURITY_LEVEL,
        )
        .unwrap();
        (store, batch)
    }

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
            miden_protocol::testing::dummy_execution_proof(),
        )
        .unwrap()
    }
}

#[tokio::test]
async fn is_account_allowed_respects_enforcement() {
    let store = TestStore::start().await;
    let allowlist = store.bootstrap_allowlist();
    let guard = TestServerGuard(CancellationToken::new());
    let block_producer = BlockProducerApi::new(
        Arc::clone(&store.state),
        0.into(),
        BlockProducerApiConfig::default(),
        guard.0.clone(),
    );
    let [listed, unlisted] = [[0; 15], [1; 15]].map(|bytes| {
        AccountId::dummy(
            bytes,
            AccountIdVersion::Version1,
            AccountType::Private,
            AssetCallbackFlag::Disabled,
        )
    });
    allowlist.add_account(listed).await.unwrap();
    let path = DataDirectory::load(store.data_directory.clone())
        .unwrap()
        .allowlist_database_path();
    let disabled_allowlist = Arc::new(AccountAllowlist::load(&path).unwrap());

    for (admission, unlisted_allowed) in [
        (AccountAdmission::enabled(allowlist), false),
        (AccountAdmission::disabled(disabled_allowlist), true),
    ] {
        // Disabled enforcement must not depend on database availability.
        if unlisted_allowed {
            fs_err::remove_file(&path).unwrap();
        }
        let rpc = RpcService::new(
            Arc::clone(&store.state),
            RpcBackend::sequencer(
                block_producer.clone(),
                ValidatorClients::new(vec![dummy_client::<ValidatorClient>()]).unwrap(),
                admission,
            ),
            None,
            NonZeroUsize::new(1).unwrap(),
            None,
        );
        for account_id in [
            None,
            Some(proto::account::AccountId::default()),
            Some(proto::account::AccountId {
                version: Some(proto::account::account_id::Version::V1(
                    proto::account::AccountIdV1 {
                        suffix: Some(proto::primitives::Felt { value: 0 }),
                        prefix: Some(proto::primitives::Felt { value: 0 }),
                    },
                )),
            }),
        ] {
            let invalid = proto::rpc::IsAccountAllowedRequest { account_id };
            assert_eq!(
                rpc.is_account_allowed(Request::new(invalid)).await.unwrap_err().code(),
                tonic::Code::InvalidArgument
            );
        }
        for (account, expected) in [(listed, true), (unlisted, unlisted_allowed)] {
            let query = proto::rpc::IsAccountAllowedRequest { account_id: Some(account.into()) };
            let response = rpc.is_account_allowed(Request::new(query)).await.unwrap();
            assert_eq!(response.into_inner().allowed, expected);
        }
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

#[tokio::test(flavor = "multi_thread")]
async fn submission_endpoints_reject_unregistered_creation_without_partial_batch_admission() {
    let (store, batch) = TestStore::with_account_creation_batch().await;
    let transactions = batch.transactions();
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

    allowlist.add_account(transactions[0].account_id()).await.unwrap();

    let proven_batch = spawn_blocking_in_current_span({
        let batch = batch.clone();
        move || {
            let executed = BatchExecutor::new().execute(batch)?;
            LocalBatchProver::default().prove(executed)
        }
    })
    .await
    .unwrap()
    .unwrap();
    let tx = proto::sequencer::AuthenticatedTransaction {
        transaction: Some(transactions[1].as_ref().into()),
        ..Default::default()
    };
    let mut auth_inputs = Vec::new();
    for tx in transactions {
        auth_inputs.push(get_tx_inputs(&store.state, tx).await.unwrap().into());
    }
    let authenticated_batch = proto::sequencer::AuthenticatedTransactionBatch {
        proposed_batch: Some((&batch).into()),
        batch_proof: Some((&proven_batch).into()),
        auth_inputs,
    };

    for result in [
        public
            .submit_proven_tx(Request::new(proto::submission::ProvenTransactionSubmission {
                transaction: Some(transactions[1].as_ref().into()),
                sealed_transaction_inputs: Some(test_sealed_transaction_inputs()),
            }))
            .await,
        public
            .submit_proven_tx_batch(Request::new(proto::submission::TransactionBatch {
                batch: Some((&proven_batch).into()),
                proposed_batch: Some((&batch).into()),
                sealed_transaction_inputs: vec![test_sealed_transaction_inputs(); 2],
            }))
            .await,
        internal.submit_authenticated_tx(Request::new(tx)).await,
        internal
            .submit_authenticated_tx_batch(Request::new(authenticated_batch.clone()))
            .await,
    ] {
        let status = result.unwrap_err();
        assert_eq!(status.code(), tonic::Code::PermissionDenied, "{status}");
        assert!(status.message().contains(&transactions[1].account_id().to_string()));
    }

    // The retry must not conflict with a partially admitted transaction from the rejected batch.
    allowlist.add_account(transactions[1].account_id()).await.unwrap();
    internal
        .submit_authenticated_tx_batch(Request::new(authenticated_batch))
        .await
        .unwrap();
}
