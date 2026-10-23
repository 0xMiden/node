use miden_node_proto::clients::ForeignAccount;
use miden_protocol::asset::FungibleAsset;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{Note, NoteType};
use miden_standards::note::P2idNote;
use opentelemetry::trace::Status;
use tokio::time::Instant;

use super::*;
use crate::db::DatabaseIdentity;
use crate::lifecycle::DATABASE_FILENAME;
use crate::node::tests::{TestChain, TestServer};
use crate::test_utils::Fixture;
use crate::test_utils::telemetry::{Telemetry, attribute};

impl FunderSetup {
    async fn fixture() -> (tempfile::TempDir, Self) {
        let fixture = Fixture::new(0, 0).unwrap();
        let fee_faucet_id = fixture.fee_faucet_id;
        let chain = fixture.chain.try_lock().unwrap();
        let faucet = chain.committed_account(fee_faucet_id).unwrap().clone();
        let witness = chain.account_witnesses([fee_faucet_id]).remove(&fee_faucet_id).unwrap();
        let fee_faucet = UsdcxFaucet::new(ForeignAccount::from_account(faucet, witness));
        let native_asset = crate::status::NativeAsset::new(
            AssetId::new_fungible(fee_faucet_id),
            &fee_faucet.metadata().unwrap(),
        );
        drop(chain);
        let directory = tempfile::tempdir().unwrap();
        let database = FundingDatabase::bootstrap(
            &directory.path().join(DATABASE_FILENAME),
            DatabaseIdentity {
                genesis_commitment: Word::empty(),
                funding_account_id: fixture.wallet.account_id(),
                fee_asset_id: AssetId::new_fungible(fee_faucet_id),
            },
        )
        .await
        .unwrap();
        (
            directory,
            Self {
                database: Arc::new(database),
                wallet: fixture.wallet,
                fee_asset_id: AssetId::new_fungible(fee_faucet_id),
                fee_faucet,
                protocol_config: ProtocolConfig::current(AssetId::new_fungible(fee_faucet_id))
                    .unwrap(),
                config: WorkerConfig {
                    max_notes_per_tx: 16.try_into().unwrap(),
                    expiration_delta: 50.try_into().unwrap(),
                    poll_interval: Duration::from_millis(1),
                },
                status: StatusSnapshot::new(fixture.funder.id(), native_asset, 1_000),
            },
        )
    }

    fn payout(&self, serial: u32) -> UsdcxP2Id {
        crate::tx::build_funding_note(
            self.wallet.account_id(),
            self.fee_asset_id,
            miden_protocol::testing::account_id::ACCOUNT_ID_SENDER.try_into().unwrap(),
            1_000,
            &mut RandomCoin::new(Word::from([serial; 4])),
        )
        .unwrap()
    }

    fn deposit(&self, serial: u32) -> Note {
        P2idNote::builder()
            .sender(self.fee_asset_id.faucet_id())
            .target(self.wallet.account_id())
            .asset(FungibleAsset::new(self.fee_asset_id.faucet_id(), 1_000).unwrap())
            .note_type(NoteType::Public)
            .serial_number(Word::from([serial; 4]))
            .build()
            .unwrap()
            .into()
    }
}

impl Funder {
    async fn reserve_attempt(
        &self,
        notes: &[UsdcxP2Id],
        deposit: Option<&Note>,
    ) -> TransactionAttempt {
        let attempt = TransactionAttempt {
            transaction_id: TransactionId::from_raw(Word::empty()),
            reference_block: 10.into(),
            expiration_block: 20.into(),
            deposit_nullifier: deposit.map(Note::nullifier),
            note_ids: notes.iter().map(|note| note.note().id()).collect(),
        };
        self.setup.database.start_attempt(attempt.clone()).await.unwrap();
        attempt
    }
}

/// Populates the wallet through its normal synchronization path.
async fn with_deposits(
    mut setup: FunderSetup,
    mut chain: TestChain,
    notes: &[Note],
) -> (Funder, TestServer) {
    let account = setup.wallet.account().as_ref().clone();
    let witness = miden_protocol::block::account_tree::AccountTree::with_entries([(
        account.id(),
        account.to_commitment(),
    )])
    .unwrap()
    .open(account.id());
    chain.account = Some((account, witness));
    chain.notes = notes.iter().cloned().map(|note| (3, note)).collect();
    let tip = chain.tip.into();
    let server = TestServer::start(chain).await;
    let update = setup.wallet.sync_to(&mut server.node.rpc_client(), tip).await.unwrap();
    setup.wallet.apply(update).unwrap();
    (Funder::new(server.node.clone(), Prover::local(), setup), server)
}

#[tokio::test]
async fn a_failure_before_submission_releases_requests_for_retry() {
    let fixture = Fixture::new(10_000, 0).unwrap();
    let chain = fixture.chain.lock().await;
    let inputs = ChainState {
        reference_header: chain.latest_block_header(),
        blockchain: chain.latest_partial_blockchain(),
    };
    let faucet = chain.committed_account(fixture.fee_faucet_id).unwrap().clone();
    let witness = chain
        .account_witnesses([fixture.fee_faucet_id])
        .remove(&fixture.fee_faucet_id)
        .unwrap();
    drop(chain);
    let mut rpc_chain = TestChain::new(inputs.reference_header.block_num().as_u32());
    rpc_chain.account = Some((faucet.clone(), witness.clone()));
    rpc_chain.unavailable_for = Some(("GetTransactionEncryptionKey", 1));
    let server = TestServer::start(rpc_chain).await;
    let (_directory, mut setup) = FunderSetup::fixture().await;
    setup.wallet = fixture.wallet;
    setup.fee_faucet = UsdcxFaucet::new(ForeignAccount::from_account(faucet, witness));
    let payout = setup.payout(1);
    setup.database.store_request(payout.clone()).await.unwrap();
    let mut funder = Funder::new(server.node.clone(), Prover::local(), setup);

    let error = funder
        .submit(
            inputs,
            Selection {
                deposit: None,
                notes: vec![payout.clone()],
            },
        )
        .await
        .unwrap_err();

    assert_eq!(error.downcast_ref::<tonic::Status>().unwrap().code(), tonic::Code::Unavailable);
    assert_eq!(
        server.chain.lock().unwrap().unavailable_for,
        Some(("GetTransactionEncryptionKey", 0))
    );
    assert!(funder.setup.database.active_attempt().await.unwrap().is_none());
    assert_eq!(funder.pending_requests().await.unwrap(), VecDeque::from([payout]));
}

#[tokio::test]
async fn state_conflict_discards_only_the_selected_deposit() {
    let (telemetry, _guard) = Telemetry::capture();
    let (_directory, setup) = FunderSetup::fixture().await;
    let deposit = setup.deposit(1);
    let unselected = setup.deposit(2);
    let payout = setup.payout(3);
    let (mut funder, _server) =
        with_deposits(setup, TestChain::new(20), &[deposit.clone(), unselected.clone()]).await;
    funder.setup.database.store_request(payout.clone()).await.unwrap();
    let status =
        tonic::Status::with_details(tonic::Code::InvalidArgument, "conflict", vec![2].into());
    let attempt = funder.reserve_attempt(std::slice::from_ref(&payout), Some(&deposit)).await;
    funder
        .resolve_attempt(attempt, Some(SubmissionOutcome::Rejected(status)))
        .await
        .unwrap();

    assert_eq!(
        &funder
            .setup
            .wallet
            .deposits()
            .iter()
            .map(|(key, deposit)| (*key, deposit.note().clone()))
            .collect::<HashMap<_, _>>(),
        &HashMap::from([(unselected.nullifier(), unselected)])
    );
    assert_eq!(funder.pending_requests().await.unwrap(), VecDeque::from([payout]));
    let span = telemetry.span("funding.resolve_attempt");
    assert_eq!(attribute(&span, "funding.outcome"), Some("deposit_discarded".into()));
    assert!(matches!(span.status, Status::Error { .. }));
}

#[tokio::test]
async fn other_rejections_preserve_notes() {
    for details in [vec![0], vec![3], vec![], vec![2, 0]] {
        let (telemetry, _guard) = Telemetry::capture();
        let (_directory, setup) = FunderSetup::fixture().await;
        let deposit = setup.deposit(1);
        let payout = setup.payout(2);
        let (mut funder, _server) =
            with_deposits(setup, TestChain::new(20), std::slice::from_ref(&deposit)).await;
        funder.setup.database.store_request(payout.clone()).await.unwrap();
        let status =
            tonic::Status::with_details(tonic::Code::InvalidArgument, "rejected", details.into());
        let attempt = funder.reserve_attempt(std::slice::from_ref(&payout), Some(&deposit)).await;
        assert!(
            funder
                .resolve_attempt(attempt, Some(SubmissionOutcome::Rejected(status)))
                .await
                .is_err()
        );

        assert_eq!(
            &funder
                .setup
                .wallet
                .deposits()
                .iter()
                .map(|(key, deposit)| (*key, deposit.note().clone()))
                .collect::<HashMap<_, _>>(),
            &HashMap::from([(deposit.nullifier(), deposit)])
        );
        assert_eq!(funder.pending_requests().await.unwrap(), VecDeque::from([payout]));
        let span = telemetry.span("funding.resolve_attempt");
        assert_eq!(attribute(&span, "funding.outcome"), Some("rejected".into()));
        assert!(matches!(span.status, Status::Error { .. }));
    }
}

#[tokio::test]
async fn accepted_and_uncertain_submissions_wait_for_commitment_or_expiration() {
    for accepted in [true, false] {
        for committed in [true, false] {
            let (telemetry, _guard) = Telemetry::capture();
            let (_directory, setup) = FunderSetup::fixture().await;
            let deposit = setup.deposit(1);
            let payout = setup.payout(2);
            let waiting = setup.payout(3);
            let transaction_id = TransactionId::from_raw(Word::empty());
            let mut chain = TestChain::new(20);
            if committed {
                chain.transactions.push((19, setup.wallet.account_id(), transaction_id));
            }
            let (mut funder, server) =
                with_deposits(setup, chain, std::slice::from_ref(&deposit)).await;
            funder.setup.database.store_request(payout.clone()).await.unwrap();
            funder.setup.database.store_request(waiting.clone()).await.unwrap();
            let outcome = if accepted {
                SubmissionOutcome::Accepted
            } else {
                SubmissionOutcome::Unknown(tonic::Status::unavailable("connection lost"))
            };
            let attempt =
                funder.reserve_attempt(std::slice::from_ref(&payout), Some(&deposit)).await;
            funder.resolve_attempt(attempt, Some(outcome)).await.unwrap();
            assert!(funder.setup.database.active_attempt().await.unwrap().is_none());

            let span = telemetry.span("funding.resolve_attempt");
            let traceparent =
                format!("00-{}-{}-01", span.span_context.trace_id(), span.span_context.span_id());
            assert!(
                server
                    .chain
                    .lock()
                    .unwrap()
                    .traceparents
                    .iter()
                    .any(|value| value == &traceparent)
            );
            assert_eq!(
                attribute(&span, "funding.submission_outcome"),
                Some(if accepted { "accepted" } else { "unknown" }.into())
            );
            assert_eq!(
                attribute(&span, "funding.outcome"),
                Some(if committed { "committed" } else { "expired" }.into())
            );
            assert_eq!(attribute(&span, "transaction.id"), Some(transaction_id.to_string().into()));
            assert_eq!(attribute(&span, "poll.count"), Some("1".into()));
            assert_eq!(matches!(span.status, Status::Error { .. }), !committed);
            assert!(
                !telemetry
                    .spans()
                    .iter()
                    .any(|span| span.name == "funding.node.transaction_status")
            );
            if committed {
                let stored =
                    funder.setup.database.request(payout.note().id()).await.unwrap().unwrap();
                let delivery = stored.delivery.unwrap();
                assert_eq!(stored.note, *payout.note());
                assert_eq!(delivery.transaction_id, transaction_id);
                assert_eq!(delivery.committed_in_block, BlockNumber::from(19));
                assert!(funder.setup.wallet.deposits().is_empty());
                assert_eq!(funder.pending_requests().await.unwrap(), VecDeque::from([waiting]));
            } else {
                assert_eq!(
                    &funder
                        .setup
                        .wallet
                        .deposits()
                        .iter()
                        .map(|(key, deposit)| (*key, deposit.note().clone()))
                        .collect::<HashMap<_, _>>(),
                    &HashMap::from([(deposit.nullifier(), deposit)])
                );
                assert_eq!(
                    funder.pending_requests().await.unwrap(),
                    VecDeque::from([payout, waiting])
                );
            }
        }
    }
}

#[tokio::test]
async fn admission_uses_the_reference_blocks_fee() {
    use miden_node_proto::generated::miden::node::v1::SyncChainMmrResponse;
    use miden_protocol::crypto::merkle::mmr::{Forest, MmrDelta};

    let fixture = Fixture::new(1_000, 100).unwrap();
    let chain = fixture.chain.lock().await;
    let header = chain.genesis_block_header().clone();
    let witness = chain
        .account_witnesses([fixture.funder.id()])
        .remove(&fixture.funder.id())
        .unwrap();
    drop(chain);
    let mut rpc_chain = TestChain::new(0);
    rpc_chain.account = Some((fixture.funder, witness));
    rpc_chain.chain_mmr = Some(SyncChainMmrResponse {
        block_header: Some(header.into()),
        mmr_delta: Some(
            MmrDelta {
                forest: Forest::new(0).unwrap(),
                data: Vec::new(),
            }
            .into(),
        ),
        ..Default::default()
    });
    let server = TestServer::start(rpc_chain).await;
    let (_directory, mut setup) = FunderSetup::fixture().await;
    setup.wallet = fixture.wallet;
    let payout = setup.payout(1);
    let mut funder = Funder::new(server.node.clone(), Prover::local(), setup);
    funder.setup.database.store_request(payout.clone()).await.unwrap();

    funder.process_batch().await.unwrap();

    assert_eq!(funder.pending_requests().await.unwrap(), VecDeque::from([payout]));
    assert_eq!(funder.setup.status.balance(), 1_000);
    assert_eq!(funder.setup.status.verification_base_fee(), 100);
}

/// Waits until a funding attempt has finished while the caller drives the worker.
async fn wait_for_attempts(telemetry: &Telemetry, count: usize) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if telemetry
                .spans()
                .iter()
                .filter(|span| span.name == "funding.process_batch")
                .count()
                >= count
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("the worker should finish the expected attempts");
}

#[tokio::test]
async fn a_restarted_worker_loads_pending_requests_in_bounded_acceptance_order() {
    let server = TestServer::start(TestChain::new(20)).await;
    let (directory, mut setup) = FunderSetup::fixture().await;
    setup.config.max_notes_per_tx = 2.try_into().unwrap();
    let notes: Vec<_> = (1..=3).map(|serial| setup.payout(serial)).collect();
    for note in &notes {
        setup.database.store_request(note.clone()).await.unwrap();
    }
    let identity = setup.database.identity();
    drop(setup.database);
    setup.database = Arc::new(
        FundingDatabase::open_and_verify(
            &directory.path().join(DATABASE_FILENAME),
            identity.genesis_commitment,
            identity.fee_asset_id,
        )
        .await
        .unwrap(),
    );
    let funder = Funder::new(server.node.clone(), Prover::local(), setup);
    assert_eq!(funder.pending_requests().await.unwrap(), VecDeque::from(notes[..2].to_vec()));
    let (telemetry, _guard) = Telemetry::capture();
    let shutdown = CancellationToken::new();
    let mut worker = Box::pin(funder.run(shutdown.clone()));
    tokio::select! {
        result = &mut worker => panic!("worker stopped: {result:?}"),
        () = wait_for_attempts(&telemetry, 1) => {},
    }
    shutdown.cancel();
    worker.await.unwrap();
    let span = telemetry.span("funding.process_batch");
    assert_eq!(attribute(&span, "queued.count"), Some("2".into()));
}

#[tokio::test]
async fn pending_requests_are_discovered_and_retried_without_an_http_server() {
    let server = TestServer::start(TestChain::new(20)).await;
    let (_directory, mut setup) = FunderSetup::fixture().await;
    setup.config.poll_interval = Duration::from_millis(50);
    let notes = [setup.payout(1), setup.payout(2)];
    let database = Arc::clone(&setup.database);
    let funder = Funder::new(server.node.clone(), Prover::local(), setup);
    let (telemetry, _guard) = Telemetry::capture();
    let shutdown = CancellationToken::new();
    let mut worker = Box::pin(funder.run(shutdown.clone()));
    tokio::select! {
        result = &mut worker => panic!("worker stopped: {result:?}"),
        () = wait_for_attempts(&telemetry, 1) => {},
    }
    for note in notes {
        database.store_request(note).await.unwrap();
    }
    let start = Instant::now();
    tokio::select! {
        result = &mut worker => panic!("worker dropped pending requests: {result:?}"),
        () = wait_for_attempts(&telemetry, 3) => {},
    }
    assert!(start.elapsed() >= Duration::from_millis(50));
    shutdown.cancel();
    worker.await.unwrap();
    let spans = telemetry.spans();
    let attempts: Vec<_> =
        spans.iter().filter(|span| span.name == "funding.process_batch").collect();
    assert!(
        attempts[1..]
            .iter()
            .all(|span| attribute(span, "queued.count") == Some("2".into()))
    );
}

#[rstest::rstest]
#[case(true)]
#[case(false)]
#[tokio::test]
async fn a_restarted_worker_waits_for_the_recorded_attempt_before_retrying_requests(
    #[case] committed: bool,
) {
    let (directory, mut setup) = FunderSetup::fixture().await;
    let payout = setup.payout(1);
    let waiting = setup.payout(2);
    setup.database.store_request(payout.clone()).await.unwrap();
    setup.database.store_request(waiting.clone()).await.unwrap();
    let attempt = TransactionAttempt {
        transaction_id: TransactionId::from_raw(Word::empty()),
        reference_block: 10.into(),
        expiration_block: 20.into(),
        deposit_nullifier: None,
        note_ids: vec![payout.note().id()],
    };
    setup.database.start_attempt(attempt.clone()).await.unwrap();
    let identity = setup.database.identity();
    drop(setup.database);
    setup.database = Arc::new(
        FundingDatabase::open_and_verify(
            &directory.path().join(DATABASE_FILENAME),
            identity.genesis_commitment,
            identity.fee_asset_id,
        )
        .await
        .unwrap(),
    );
    let database = Arc::clone(&setup.database);
    let mut chain = TestChain::new(20);
    chain.unavailable = Some("SyncTransactions");
    let server = TestServer::start(chain).await;
    let mut funder = Funder::new(server.node.clone(), Prover::local(), setup);

    {
        let mut recovery = Box::pin(funder.process_batch());
        assert!(tokio::time::timeout(Duration::from_millis(50), &mut recovery).await.is_err());
        assert_eq!(database.active_attempt().await.unwrap(), Some(attempt.clone()));
        assert_eq!(database.pending_requests(2.try_into().unwrap()).await.unwrap().len(), 1);

        {
            let mut chain = server.chain.lock().unwrap();
            chain.tip = 15;
            chain.unavailable = None;
        }
        assert!(tokio::time::timeout(Duration::from_millis(50), &mut recovery).await.is_err());
        assert_eq!(database.active_attempt().await.unwrap(), Some(attempt.clone()));
        {
            let mut chain = server.chain.lock().unwrap();
            chain.tip = 20;
            if committed {
                chain
                    .transactions
                    .push((19, identity.funding_account_id, attempt.transaction_id));
            }
        }
        tokio::time::timeout(Duration::from_secs(5), recovery).await.unwrap().unwrap();
    }

    assert!(database.active_attempt().await.unwrap().is_none());
    let delivered = database.request(payout.note().id()).await.unwrap().unwrap();
    if committed {
        let delivery = delivered.delivery.unwrap();
        assert_eq!(delivery.transaction_id, attempt.transaction_id);
        assert_eq!(delivery.committed_in_block, BlockNumber::from(19));
        assert_eq!(funder.pending_requests().await.unwrap(), VecDeque::from([waiting]));
    } else {
        assert!(delivered.delivery.is_none());
        assert_eq!(funder.pending_requests().await.unwrap(), VecDeque::from([payout, waiting]));
    }
}

#[tokio::test]
async fn shutdown_stops_an_idle_worker() {
    let server = TestServer::start(TestChain::new(20)).await;
    let (_directory, setup) = FunderSetup::fixture().await;
    let funder = Funder::new(server.node.clone(), Prover::local(), setup);
    let shutdown = CancellationToken::new();
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(5), funder.run(shutdown))
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn a_confirmed_batch_waits_for_its_delivery_record_even_if_the_node_goes_offline() {
    use miden_node_db::DatabaseError;

    let (directory, setup) = FunderSetup::fixture().await;
    let payout = setup.payout(1);
    setup.database.store_request(payout.clone()).await.unwrap();
    let database = Arc::clone(&setup.database);
    let transaction_id = TransactionId::from_raw(Word::empty());
    let mut chain = TestChain::new(20);
    chain.transactions.push((19, setup.wallet.account_id(), transaction_id));
    let server = TestServer::start(chain).await;
    let mut funder = Funder::new(server.node.clone(), Prover::local(), setup);
    let attempt = funder.reserve_attempt(std::slice::from_ref(&payout), None).await;
    let (writer, _reader) =
        miden_node_db::sqlite::open(&directory.path().join(DATABASE_FILENAME)).unwrap();
    writer
        .write("reject funding delivery updates", |tx| {
            tx.execute(
                "CREATE TRIGGER reject_delivery BEFORE UPDATE ON requests
                    BEGIN SELECT RAISE(FAIL, 'audit unavailable'); END",
                &[],
            )?;
            Ok::<_, DatabaseError>(())
        })
        .await
        .unwrap();
    let resolution = funder.resolve_attempt(attempt.clone(), Some(SubmissionOutcome::Accepted));
    tokio::pin!(resolution);
    assert!(tokio::time::timeout(Duration::from_millis(50), &mut resolution).await.is_err());
    assert!(database.request(payout.note().id()).await.unwrap().unwrap().delivery.is_none());
    assert_eq!(database.active_attempt().await.unwrap(), Some(attempt));
    server.chain.lock().unwrap().unavailable = Some("SyncTransactions");
    writer
        .write("restore funding delivery updates", |tx| {
            tx.execute("DROP TRIGGER reject_delivery", &[])?;
            Ok::<_, DatabaseError>(())
        })
        .await
        .unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), resolution).await.unwrap().unwrap(),
        Resolution::Committed
    ));
    let stored = database.request(payout.note().id()).await.unwrap().unwrap();
    assert_eq!(stored.delivery.unwrap().committed_in_block, BlockNumber::from(19));
    assert!(database.pending_requests(1.try_into().unwrap()).await.unwrap().is_empty());
    assert!(database.active_attempt().await.unwrap().is_none());
}

#[rstest::rstest]
#[case(1)]
#[case(80)]
#[tokio::test]
async fn a_recovered_poll_error_does_not_mark_commitment_as_failed(#[case] failures: usize) {
    let (_directory, setup) = FunderSetup::fixture().await;
    let payout = setup.payout(1);
    setup.database.store_request(payout.clone()).await.unwrap();
    let transaction_id = TransactionId::from_raw(Word::empty());
    let mut chain = TestChain::new(20);
    chain.transactions.push((19, setup.wallet.account_id(), transaction_id));
    chain.unavailable_for = Some(("SyncTransactions", failures));
    let server = TestServer::start(chain).await;
    let mut funder = Funder::new(server.node.clone(), Prover::local(), setup);
    let attempt = funder.reserve_attempt(&[payout], None).await;
    let (telemetry, _guard) = Telemetry::capture();
    funder
        .resolve_attempt(attempt, Some(SubmissionOutcome::Accepted))
        .await
        .unwrap();
    let span = telemetry.span("funding.resolve_attempt");
    assert_eq!(attribute(&span, "funding.outcome"), Some("committed".into()));
    assert_eq!(attribute(&span, "poll.count"), Some((failures + 1).to_string().into()));
    assert_eq!(attribute(&span, "poll.error.count"), Some(failures.to_string().into()));
    assert!(!matches!(span.status, Status::Error { .. }));
    assert_eq!(span.dropped_attributes_count, 0);
    let spans = telemetry.spans();
    let failed_polls: Vec<_> =
        spans.iter().filter(|span| span.name == "funding.poll_failure").collect();
    assert_eq!(failed_polls.len(), failures);
    for failed_poll in failed_polls {
        assert_eq!(failed_poll.parent_span_id, span.span_context.span_id());
        assert!(matches!(failed_poll.status, Status::Error { .. }));
        assert!(failed_poll.events.iter().any(|event| {
            event.attributes.iter().any(|attr| attr.key.as_str() == "exception.message")
        }));
    }
}
