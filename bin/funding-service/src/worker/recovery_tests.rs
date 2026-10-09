use miden_protocol::asset::FungibleAsset;
use miden_protocol::note::NoteType;
use miden_standards::note::P2idNote;
use opentelemetry::trace::{SpanId, Status};

use super::*;
use crate::node::tests::{TestChain, TestServer};
use crate::test_utils::telemetry::{Telemetry, attribute};
use crate::test_utils::{funder_key_from, genesis_style_wallet, test_native_asset};

impl FunderSetup {
    fn fixture() -> Self {
        let fee_faucet_id = FungibleAsset::mock_issuer();
        let (account, key) = genesis_style_wallet(fee_faucet_id, 0, [71; 32]).unwrap();
        Self {
            key: funder_key_from(&account, &key).unwrap(),
            fee_asset_id: AssetId::new_fungible(fee_faucet_id),
            verification_base_fee: 0,
            protocol_config: ProtocolConfig::current(AssetId::new_fungible(fee_faucet_id)).unwrap(),
            config: WorkerConfig {
                max_notes_per_tx: 16.try_into().unwrap(),
                expiration_delta: 50.try_into().unwrap(),
                tick_interval: Duration::from_millis(1),
                deposit_scan_interval: Duration::from_secs(60),
            },
            status: StatusSnapshot::new(account.id(), test_native_asset(), 1_000),
        }
    }

    fn deposit(&self, serial: u32) -> Note {
        P2idNote::builder()
            .sender(self.fee_asset_id.faucet_id())
            .target(self.key.account_id())
            .asset(FungibleAsset::new(self.fee_asset_id.faucet_id(), 1_000).unwrap())
            .note_type(NoteType::Public)
            .serial_number(Word::from([serial; 4]))
            .build()
            .unwrap()
            .into()
    }
}

#[tokio::test]
async fn startup_recovers_unspent_deposits_after_a_failed_scan() {
    let (telemetry, _guard) = Telemetry::capture();
    let setup = FunderSetup::fixture();
    let spent = setup.deposit(1);
    let unspent = setup.deposit(2);
    let mut chain = TestChain::new(12);
    chain.notes = vec![(3, spent.clone()), (10, unspent.clone())];
    chain.spent = vec![(4, spent.nullifier())];
    chain.unavailable = Some("SyncNullifiers");
    let server = TestServer::start(chain).await;
    let mut scanner = DepositScanner::new(setup.key.account_id(), setup.fee_asset_id);
    let mut funder = Funder::new(server.node.clone(), Prover::local(), setup);

    assert!(funder.sync_initial_deposits(&mut scanner, 12.into()).await.is_err());
    assert_eq!(funder.deposits.len(), 2);
    server.chain.lock().unwrap().unavailable = None;
    funder.sync_initial_deposits(&mut scanner, 12.into()).await.unwrap();
    assert_eq!(funder.deposits, HashMap::from([(unspent.nullifier(), unspent)]));
    let spans = telemetry.spans();
    let recovery: Vec<_> =
        spans.iter().filter(|span| span.name == "funding.recover_deposits").collect();
    assert_eq!(recovery.len(), 2);
    assert!(matches!(recovery[0].status, Status::Error { .. }));
    assert!(!matches!(recovery[1].status, Status::Error { .. }));
    assert_eq!(attribute(recovery[1], "deposit.count"), Some("1".into()));
    assert_eq!(attribute(recovery[1], "deposit.spent.count"), Some("1".into()));
    assert!(recovery.iter().all(|span| span.parent_span_id == SpanId::INVALID));
    let discovery = spans
        .iter()
        .find(|span| {
            span.name == "funding.discover_deposits"
                && span.parent_span_id == recovery[0].span_context.span_id()
        })
        .unwrap();
    assert_eq!(attribute(discovery, "deposit.count"), Some("2".into()));
    assert_eq!(attribute(discovery, "page.count"), Some("3".into()));
    assert_eq!(
        discovery
            .attributes
            .iter()
            .filter(|attr| attr.key.as_str() == "deposit.count")
            .count(),
        1
    );
}

#[tokio::test]
async fn state_conflict_discards_only_the_selected_deposit() {
    let (telemetry, _guard) = Telemetry::capture();
    let setup = FunderSetup::fixture();
    let deposit = setup.deposit(1);
    let unselected = setup.deposit(2);
    let payout = setup.deposit(3);
    let server = TestServer::start(TestChain::new(20)).await;
    let mut funder = Funder::new(server.node.clone(), Prover::local(), setup);
    funder.deposits = [deposit.clone(), unselected.clone()]
        .into_iter()
        .map(|note| (note.nullifier(), note))
        .collect();
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
                deposit: Some(deposit),
                notes: vec![payout.clone()],
            },
        )
        .await
        .unwrap();

    assert_eq!(funder.deposits, HashMap::from([(unselected.nullifier(), unselected)]));
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
        let payout = setup.deposit(2);
        let server = TestServer::start(TestChain::new(20)).await;
        let mut funder = Funder::new(server.node.clone(), Prover::local(), setup);
        funder.deposits.insert(deposit.nullifier(), deposit.clone());
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
                        deposit: Some(deposit.clone()),
                        notes: vec![payout.clone()]
                    },
                )
                .await
                .is_err()
        );

        assert_eq!(funder.deposits, HashMap::from([(deposit.nullifier(), deposit)]));
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
            let payout = setup.deposit(2);
            let waiting = setup.deposit(3);
            let transaction_id = TransactionId::from_raw(Word::empty());
            let mut chain = TestChain::new(20);
            if committed {
                chain.transactions.push((19, setup.key.account_id(), transaction_id));
            }
            let server = TestServer::start(chain).await;
            let mut funder = Funder::new(server.node.clone(), Prover::local(), setup);
            funder.deposits.insert(deposit.nullifier(), deposit.clone());
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
                        deposit: Some(deposit.clone()),
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
                assert!(funder.deposits.is_empty());
                assert_eq!(funder.queued, VecDeque::from([waiting]));
            } else {
                assert_eq!(funder.deposits, HashMap::from([(deposit.nullifier(), deposit)]));
                assert_eq!(funder.queued, VecDeque::from([payout, waiting]));
            }
        }
    }
}

#[tokio::test]
async fn empty_worker_ticks_do_not_export_spans() {
    let server = TestServer::start(TestChain::new(20)).await;
    let mut funder = Funder::new(server.node.clone(), Prover::local(), FunderSetup::fixture());
    let (telemetry, _guard) = Telemetry::capture();
    for _ in 0..3 {
        funder.process_pending_notes().await.unwrap();
    }
    assert!(telemetry.spans().is_empty());
}

#[rstest::rstest]
#[case(1)]
#[case(80)]
#[tokio::test]
async fn a_recovered_poll_error_does_not_mark_commitment_as_failed(#[case] failures: usize) {
    let setup = FunderSetup::fixture();
    let transaction_id = TransactionId::from_raw(Word::empty());
    let mut chain = TestChain::new(20);
    chain.transactions.push((19, setup.key.account_id(), transaction_id));
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
