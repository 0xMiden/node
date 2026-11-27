use std::collections::{BTreeMap, BTreeSet};

use axum::body::{Body, to_bytes};
use axum::http::Request;
use miden_node_store::{BlockWriter, GenesisState, State as StoreState, WriterTask};
use miden_node_utils::clap::StorageOptions;
use miden_node_utils::fee::{test_fee_params, test_protocol_config};
use miden_node_utils::shutdown::CancellationToken;
use miden_protocol::testing::random_secret_key::random_secret_key;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::*;

struct TestSequencer {
    directory: tempfile::TempDir,
    config: ValidatorConfigState,
    writer: BlockWriter,
    writer_task: WriterTask,
    app: Router,
}

impl TestSequencer {
    async fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let config =
            ValidatorConfig::new((0..3).map(|_| random_secret_key().public_key()).collect(), 3)
                .unwrap();
        let genesis =
            GenesisState::new(Vec::new(), test_fee_params(), 0, config, test_protocol_config())
                .into_block()
                .unwrap();
        StoreState::bootstrap(genesis, directory.path()).await.unwrap();
        let (state, writer, _proof_writer, writer_task) =
            StoreState::load(directory.path(), StorageOptions::default())
                .await
                .unwrap()
                .start(CancellationToken::new());
        let config = ValidatorConfigState::new(state);
        let allowlist_path = directory.path().join("allowlist.sqlite3");
        miden_node_store::allowlist::AccountAllowlist::bootstrap(&allowlist_path).unwrap();
        let allowlist = std::sync::Arc::new(
            miden_node_store::allowlist::AccountAllowlist::load(allowlist_path).unwrap(),
        );
        let app = crate::admin::router(allowlist, None, router(config.clone()));
        Self {
            directory,
            config,
            writer,
            writer_task,
            app,
        }
    }

    async fn stop(self) {
        self.writer.stop(self.writer_task).await;
    }

    async fn pending(&self, quorum: u16) {
        *self.config.pending.lock().await =
            Some(PendingValidatorQuorum { quorum, activation_height: 10.into() });
    }

    fn restart(&mut self) {
        self.config = ValidatorConfigState::new(std::sync::Arc::clone(&self.config.state));
        let allowlist = std::sync::Arc::new(
            miden_node_store::allowlist::AccountAllowlist::load(
                self.directory.path().join("allowlist.sqlite3"),
            )
            .unwrap(),
        );
        self.app = crate::admin::router(allowlist, None, router(self.config.clone()));
    }

    async fn request(&self, method: &str, body: Option<Value>) -> (StatusCode, Value) {
        self.request_at(method, body, Some(10)).await
    }

    async fn request_at(
        &self,
        method: &str,
        body: Option<Value>,
        activation_height: Option<u32>,
    ) -> (StatusCode, Value) {
        request(&self.app, method, body, activation_height).await
    }
}

async fn request(
    app: &Router,
    method: &str,
    body: Option<Value>,
    activation_height: Option<u32>,
) -> (StatusCode, Value) {
    let path = if method == "GET" {
        "/admin/v1/validator-config"
    } else {
        "/admin/v1/validator-config/pending"
    };
    let path = if method == "GET" {
        path.to_owned()
    } else {
        activation_height
            .map_or_else(|| path.to_owned(), |height| format!("{path}?activation_height={height}"))
    };
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .body(body.map_or_else(Body::empty, |value| Body::from(value.to_string())))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.headers()["cache-control"], "no-store");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

#[tokio::test]
async fn status_reports_committed_quorum_and_registered_change() {
    let sequencer = TestSequencer::new().await;
    assert_eq!(
        sequencer.request("GET", None).await,
        (StatusCode::OK, json!({"active":3,"pending":null,"activation_height":null}))
    );
    sequencer.pending(2).await;
    assert_eq!(
        sequencer.request("GET", None).await,
        (StatusCode::OK, json!({"active":3,"pending":2,"activation_height":10}))
    );
    sequencer.stop().await;
}

#[tokio::test]
async fn registration_rejects_invalid_changes() {
    let sequencer = TestSequencer::new().await;
    for (change, status, error) in [
        (json!({"active":3,"pending":0}), StatusCode::BAD_REQUEST, "greater than zero"),
        (json!({"active":3,"pending":3}), StatusCode::BAD_REQUEST, "identical"),
        (json!({"active":3,"pending":4}), StatusCode::BAD_REQUEST, "exceeds"),
        (json!({"active":4,"pending":2}), StatusCode::CONFLICT, "does not match"),
    ] {
        let (actual, body) = sequencer.request("PUT", Some(change)).await;
        assert_eq!(actual, status, "{body}");
        assert!(body["error"].as_str().unwrap().contains(error), "{body}");
    }
    let (status, _) =
        sequencer.request("PUT", Some(json!({"active":3,"pending":2,"keys":[]}))).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        sequencer.request("GET", None).await.1,
        json!({"active":3,"pending":null,"activation_height":null})
    );
    sequencer.stop().await;
}

#[tokio::test]
async fn cancellation_requires_the_registered_change_file() {
    let sequencer = TestSequencer::new().await;
    sequencer.pending(2).await;
    for change in [json!({"active":3,"pending":1}), json!({"active":4,"pending":2})] {
        assert_eq!(sequencer.request("DELETE", Some(change)).await.0, StatusCode::CONFLICT);
        assert_eq!(
            sequencer.request("GET", None).await.1,
            json!({"active":3,"pending":2,"activation_height":10})
        );
    }
    let change = json!({"active":3,"pending":2});
    assert_eq!(
        sequencer.request("DELETE", Some(change.clone())).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        sequencer.request("GET", None).await.1,
        json!({"active":3,"pending":null,"activation_height":null})
    );
    assert_eq!(sequencer.request("DELETE", Some(change)).await.0, StatusCode::CONFLICT);
    sequencer.stop().await;
}

#[tokio::test]
async fn cancellation_reports_an_already_committed_quorum() {
    let sequencer = TestSequencer::new().await;
    let (status, body) = sequencer.request("DELETE", Some(json!({"active":2,"pending":3}))).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(body["error"].as_str().unwrap().contains("already active"));
    sequencer.stop().await;
}

#[tokio::test]
async fn scheduling_requires_an_activation_height_with_an_uncommitted_transition() {
    let sequencer = TestSequencer::new().await;
    let change = json!({"active":3,"pending":2});
    assert_eq!(
        sequencer.request_at("PUT", Some(change.clone()), None).await.0,
        StatusCode::BAD_REQUEST
    );
    for height in [0, 1] {
        let (status, body) = sequencer.request_at("PUT", Some(change.clone()), Some(height)).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(body["error"].as_str().unwrap().contains("transition block"), "{body}");
    }
    let (status, body) = sequencer.request_at("PUT", Some(change), Some(2)).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert_eq!(
        sequencer.request("GET", None).await.1,
        json!({"active":3,"pending":2,"activation_height":2})
    );
    sequencer.stop().await;
}

#[tokio::test]
async fn cancellation_requires_the_registered_activation_height() {
    let sequencer = TestSequencer::new().await;
    sequencer.pending(2).await;
    let change = json!({"active":3,"pending":2});
    assert_eq!(
        sequencer.request_at("DELETE", Some(change.clone()), Some(11)).await.0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        sequencer.request("GET", None).await.1,
        json!({"active":3,"pending":2,"activation_height":10})
    );
    assert_eq!(
        sequencer.request_at("DELETE", Some(change), Some(10)).await.0,
        StatusCode::NO_CONTENT
    );
    sequencer.stop().await;
}

#[tokio::test]
async fn restarting_discards_the_schedule_and_preserves_the_chain_configuration() {
    let mut sequencer = TestSequencer::new().await;
    sequencer.pending(2).await;
    sequencer.restart();
    assert_eq!(
        sequencer.request("GET", None).await.1,
        json!({"active":3,"pending":null,"activation_height":null})
    );
    let (status, body) = sequencer.request("DELETE", Some(json!({"active":3,"pending":2}))).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("no validator quorum change is pending")
    );
    sequencer.stop().await;
}

async fn transition_block(
    state: &StoreState,
) -> (
    miden_protocol::batch::OrderedBatches,
    miden_protocol::block::BlockInputs,
    miden_protocol::block::SignedBlock,
) {
    use miden_protocol::block::{BlockInputs, BlockSignatures, ProposedBlock, SignedBlock};

    let view = state.view();
    let (parent, _) = view.get_block_header(None, false).await.unwrap();
    let chain = view.get_block_inclusion_proofs(*view.tip(), BTreeSet::new()).await.unwrap();
    let witnesses = view.get_state_witnesses(&[], &[]);
    let inputs = BlockInputs::new(
        parent.unwrap(),
        chain,
        witnesses.account_witnesses,
        witnesses.nullifier_witnesses,
        BTreeMap::new(),
    );
    let config =
        ValidatorConfig::new(inputs.prev_block_header().validator_config().keys().to_vec(), 2)
            .unwrap();
    let proposal = ProposedBlock::new(inputs.clone(), Vec::new())
        .unwrap()
        .with_next_validator_config(config);
    let batches = proposal.batches().clone();
    let (header, body) = proposal.into_header_and_body().unwrap();
    (
        batches,
        inputs,
        SignedBlock::new_unchecked(header, body, BlockSignatures::new(Vec::new()).unwrap()),
    )
}

async fn hold_database_writer(
    path: &std::path::Path,
) -> (std::sync::mpsc::Sender<()>, tokio::task::JoinHandle<()>) {
    let (writer, _reader) = miden_node_db::sqlite::open(path).unwrap();
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let task = tokio::spawn(async move {
        writer
            .write::<_, miden_node_db::DatabaseError, _>("hold block commit", move |_tx| {
                entered_tx.send(()).unwrap();
                let _ = release_rx.recv();
                Ok(())
            })
            .await
            .unwrap();
    });
    entered_rx.await.unwrap();
    (release_tx, task)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_waits_for_a_block_write_and_observes_its_commit() {
    use std::sync::Arc;
    use std::time::Duration;

    let mut sequencer = TestSequencer::new().await;
    let app = sequencer.app.clone();
    let state = Arc::clone(&sequencer.config.state);
    let pending = Arc::clone(&sequencer.config.pending);
    *pending.lock().await = Some(PendingValidatorQuorum { quorum: 2, activation_height: 2.into() });
    let (batches, inputs, block) = transition_block(&state).await;
    let directory =
        miden_node_store::DataDirectory::load(sequencer.directory.path().to_path_buf()).unwrap();
    let blocks = miden_node_store::BlockStore::load(directory.block_store_dir()).unwrap();
    let (release, held_writer) = hold_database_writer(&directory.database_path()).await;
    {
        let guard = pending.lock_owned().await;
        let write = sequencer.writer.apply_sequencer_block(batches, inputs, block, guard);
        tokio::pin!(write);
        let candidate_saved = async {
            while blocks.load_block(1.into()).await.unwrap().is_none() {
                tokio::task::yield_now().await;
            }
        };
        tokio::select! {
            result = &mut write => panic!("write finished while the database was locked: {result:?}"),
            result = tokio::time::timeout(Duration::from_secs(5), candidate_saved) => result.expect("candidate block should be saved"),
        }
        assert_eq!(state.committed_tip(), 0.into());
        // Readers can complete while the write is held, so pending cancellation cannot be
        // attributed to a blocked chain-tip query.
        assert_eq!(
            state
                .view()
                .get_block_header(None, false)
                .await
                .unwrap()
                .0
                .unwrap()
                .validator_config()
                .quorum(),
            3
        );
        let cancellation = request(&app, "DELETE", Some(json!({"active":3,"pending":2})), Some(2));
        tokio::pin!(cancellation);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut cancellation)
                .await
                .is_err()
        );
        release.send(()).unwrap();
        held_writer.await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), &mut write).await.unwrap().unwrap();
        let (status, body) =
            tokio::time::timeout(Duration::from_secs(5), &mut cancellation).await.unwrap();
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(body["error"].as_str().unwrap().contains("already active"), "{body}");
    }
    assert_eq!(state.committed_tip(), 1.into());
    assert_eq!(
        sequencer.request("GET", None).await.1,
        json!({"active":2,"pending":null,"activation_height":null})
    );
    sequencer.stop().await;
}
