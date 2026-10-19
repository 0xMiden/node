use miden_node_proto::clients::ForeignAccount;
use miden_protocol::asset::FungibleAsset;
use miden_protocol::note::{Note, NoteType};
use miden_standards::note::P2idNote;
use opentelemetry::trace::Status;

use super::*;
use crate::node::tests::{TestChain, TestServer};
use crate::test_utils::Fixture;
use crate::test_utils::telemetry::{Telemetry, attribute};

impl FunderSetup {
    fn fixture() -> Self {
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
        Self {
            wallet: fixture.wallet,
            fee_asset_id: AssetId::new_fungible(fee_faucet_id),
            fee_faucet,
            protocol_config: ProtocolConfig::current(AssetId::new_fungible(fee_faucet_id)).unwrap(),
            config: WorkerConfig {
                max_notes_per_tx: 16.try_into().unwrap(),
                expiration_delta: 50.try_into().unwrap(),
                poll_interval: Duration::from_millis(1),
            },
            status: StatusSnapshot::new(fixture.funder.id(), native_asset, 1_000),
        }
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
async fn state_conflict_discards_only_the_selected_deposit() {
    let (telemetry, _guard) = Telemetry::capture();
    let setup = FunderSetup::fixture();
    let deposit = setup.deposit(1);
    let unselected = setup.deposit(2);
    let payout = UsdcxP2Id::from_note(setup.deposit(3), setup.fee_asset_id).unwrap();
    let (mut funder, _server) =
        with_deposits(setup, TestChain::new(20), &[deposit.clone(), unselected.clone()]).await;
    funder.queued.push_back(payout.clone());
    let status =
        tonic::Status::with_details(tonic::Code::InvalidArgument, "conflict", vec![2].into());
    funder
        .resolve_submission(
            SubmissionOutcome::Rejected(status),
            TransactionId::from_raw(Word::empty()),
            10.into(),
            20.into(),
            Selection {
                deposit: UsdcxP2Id::from_note(deposit, funder.setup.fee_asset_id),
                notes: vec![payout.clone()],
            },
        )
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
    assert_eq!(funder.queued, VecDeque::from([payout]));
    let span = telemetry.span("funding.resolve_submission");
    assert_eq!(attribute(&span, "funding.outcome"), Some("deposit_discarded".into()));
    assert!(matches!(span.status, Status::Error { .. }));
}

#[tokio::test]
async fn other_rejections_preserve_notes() {
    for details in [vec![0], vec![3], vec![], vec![2, 0]] {
        let (telemetry, _guard) = Telemetry::capture();
        let setup = FunderSetup::fixture();
        let deposit = setup.deposit(1);
        let payout = UsdcxP2Id::from_note(setup.deposit(2), setup.fee_asset_id).unwrap();
        let (mut funder, _server) =
            with_deposits(setup, TestChain::new(20), std::slice::from_ref(&deposit)).await;
        funder.queued.push_back(payout.clone());
        let status =
            tonic::Status::with_details(tonic::Code::InvalidArgument, "rejected", details.into());
        assert!(
            funder
                .resolve_submission(
                    SubmissionOutcome::Rejected(status),
                    TransactionId::from_raw(Word::empty()),
                    10.into(),
                    20.into(),
                    Selection {
                        deposit: UsdcxP2Id::from_note(deposit.clone(), funder.setup.fee_asset_id),
                        notes: vec![payout.clone()]
                    },
                )
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
        assert_eq!(funder.queued, VecDeque::from([payout]));
        let span = telemetry.span("funding.resolve_submission");
        assert_eq!(attribute(&span, "funding.outcome"), Some("rejected".into()));
        assert!(matches!(span.status, Status::Error { .. }));
    }
}

#[tokio::test]
async fn accepted_and_uncertain_submissions_wait_for_commitment_or_expiration() {
    for accepted in [true, false] {
        for committed in [true, false] {
            let (telemetry, _guard) = Telemetry::capture();
            let setup = FunderSetup::fixture();
            let deposit = setup.deposit(1);
            let payout = UsdcxP2Id::from_note(setup.deposit(2), setup.fee_asset_id).unwrap();
            let waiting = UsdcxP2Id::from_note(setup.deposit(3), setup.fee_asset_id).unwrap();
            let transaction_id = TransactionId::from_raw(Word::empty());
            let mut chain = TestChain::new(20);
            if committed {
                chain.transactions.push((19, setup.wallet.account_id(), transaction_id));
            }
            let (mut funder, server) =
                with_deposits(setup, chain, std::slice::from_ref(&deposit)).await;
            funder.queued = VecDeque::from([payout.clone(), waiting.clone()]);
            let outcome = if accepted {
                SubmissionOutcome::Accepted
            } else {
                SubmissionOutcome::Unknown(tonic::Status::unavailable("connection lost"))
            };
            funder
                .resolve_submission(
                    outcome,
                    transaction_id,
                    10.into(),
                    20.into(),
                    Selection {
                        deposit: UsdcxP2Id::from_note(deposit.clone(), funder.setup.fee_asset_id),
                        notes: vec![payout.clone()],
                    },
                )
                .await
                .unwrap();

            let span = telemetry.span("funding.resolve_submission");
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
                assert!(funder.setup.wallet.deposits().is_empty());
                assert_eq!(funder.queued, VecDeque::from([waiting]));
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
                assert_eq!(funder.queued, VecDeque::from([payout, waiting]));
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
    let mut setup = FunderSetup::fixture();
    setup.wallet = fixture.wallet;
    let payout = UsdcxP2Id::from_note(setup.deposit(1), setup.fee_asset_id).unwrap();
    let mut funder = Funder::new(server.node.clone(), Prover::local(), setup);
    funder.queued.push_back(payout.clone());

    funder.process_batch().await.unwrap();

    assert_eq!(funder.queued, VecDeque::from([payout]));
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
async fn a_partial_batch_waits_until_full_and_preserves_the_batch_limit() {
    let server = TestServer::start(TestChain::new(20)).await;
    let mut setup = FunderSetup::fixture();
    setup.config.max_notes_per_tx = 2.try_into().unwrap();
    setup.config.poll_interval = Duration::from_secs(60);
    let note = UsdcxP2Id::from_note(setup.deposit(1), setup.fee_asset_id).unwrap();
    let funder = Funder::new(server.node.clone(), Prover::local(), setup);
    let (sender, requests) = mpsc::channel(3);
    let (telemetry, _guard) = Telemetry::capture();
    let mut worker = Box::pin(funder.run_loop(requests));

    // The fixture rejects chain-state requests, leaving the worker waiting for its retry deadline.
    tokio::select! {
        result = &mut worker => panic!("worker stopped: {result:?}"),
        () = wait_for_attempts(&telemetry, 1) => {},
    }
    sender.try_send(note.clone()).unwrap();
    assert!(tokio::time::timeout(Duration::from_millis(50), &mut worker).await.is_err());
    assert_eq!(sender.capacity(), 3);
    assert_eq!(
        telemetry
            .spans()
            .iter()
            .filter(|span| span.name == "funding.process_batch")
            .count(),
        1
    );
    for _ in 0..2 {
        sender.try_send(note.clone()).unwrap();
    }
    tokio::select! {
        result = &mut worker => panic!("worker stopped: {result:?}"),
        () = wait_for_attempts(&telemetry, 2) => {},
    }
    assert_eq!(sender.capacity(), 2);
    assert!(tokio::time::timeout(Duration::from_millis(50), &mut worker).await.is_err());
    let spans = telemetry.spans();
    let attempts: Vec<_> =
        spans.iter().filter(|span| span.name == "funding.process_batch").collect();
    assert_eq!(attempts.len(), 2);
    assert_eq!(attribute(attempts[0], "queued.count"), Some("0".into()));
    assert_eq!(attribute(attempts[1], "queued.count"), Some("2".into()));
}

#[tokio::test]
async fn pending_requests_retry_after_the_channel_closes() {
    let server = TestServer::start(TestChain::new(20)).await;
    let mut setup = FunderSetup::fixture();
    setup.config.poll_interval = Duration::from_millis(50);
    let note = UsdcxP2Id::from_note(setup.deposit(1), setup.fee_asset_id).unwrap();
    let funder = Funder::new(server.node.clone(), Prover::local(), setup);
    let (sender, requests) = mpsc::channel(1);
    let (telemetry, _guard) = Telemetry::capture();
    let mut worker = Box::pin(funder.run_loop(requests));
    tokio::select! {
        result = &mut worker => panic!("worker stopped: {result:?}"),
        () = wait_for_attempts(&telemetry, 1) => {},
    }
    sender.try_send(note).unwrap();
    drop(sender);
    let start = Instant::now();
    tokio::select! {
        result = &mut worker => panic!("worker dropped pending requests: {result:?}"),
        () = wait_for_attempts(&telemetry, 3) => {},
    }
    assert!(start.elapsed() >= Duration::from_millis(50));
    let spans = telemetry.spans();
    let attempts: Vec<_> =
        spans.iter().filter(|span| span.name == "funding.process_batch").collect();
    assert_eq!(attempts.len(), 3);
    assert!(
        attempts[1..]
            .iter()
            .all(|span| attribute(span, "queued.count") == Some("1".into()))
    );
}

#[tokio::test]
async fn a_closed_empty_channel_stops_the_worker() {
    let server = TestServer::start(TestChain::new(20)).await;
    let funder = Funder::new(server.node.clone(), Prover::local(), FunderSetup::fixture());
    let (sender, requests) = mpsc::channel(1);
    drop(sender);
    tokio::time::timeout(Duration::from_secs(5), funder.run_loop(requests))
        .await
        .unwrap()
        .unwrap();
}

#[rstest::rstest]
#[case(1)]
#[case(80)]
#[tokio::test]
async fn a_recovered_poll_error_does_not_mark_commitment_as_failed(#[case] failures: usize) {
    let setup = FunderSetup::fixture();
    let transaction_id = TransactionId::from_raw(Word::empty());
    let mut chain = TestChain::new(20);
    chain.transactions.push((19, setup.wallet.account_id(), transaction_id));
    chain.unavailable_for = Some(("SyncTransactions", failures));
    let server = TestServer::start(chain).await;
    let mut funder = Funder::new(server.node.clone(), Prover::local(), setup);
    let (telemetry, _guard) = Telemetry::capture();
    funder
        .resolve_submission(
            SubmissionOutcome::Accepted,
            transaction_id,
            10.into(),
            20.into(),
            Selection { deposit: None, notes: Vec::new() },
        )
        .await
        .unwrap();
    let span = telemetry.span("funding.resolve_submission");
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
