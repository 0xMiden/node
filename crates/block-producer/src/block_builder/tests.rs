use miden_node_store::GenesisState;
use miden_node_utils::clap::StorageOptions;
use miden_node_utils::fee::{test_fee_params, test_protocol_config};
use miden_protocol::testing::random_secret_key::random_secret_key;

use super::*;

async fn start_store() -> (
    tempfile::TempDir,
    Arc<State>,
    BlockWriter,
    miden_node_store::WriterTask,
    ValidatorConfig,
) {
    let directory = tempfile::tempdir().unwrap();
    let config =
        ValidatorConfig::new((0..3).map(|_| random_secret_key().public_key()).collect(), 3)
            .unwrap();
    let genesis =
        GenesisState::new(Vec::new(), test_fee_params(), 0, config.clone(), test_protocol_config())
            .into_block()
            .unwrap();
    State::bootstrap(genesis, directory.path()).await.unwrap();
    let (state, writer, _proof_writer, task) =
        State::load(directory.path(), StorageOptions::default())
            .await
            .unwrap()
            .start(CancellationToken::new());

    (directory, state, writer, task, config)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quorum_proposals_preserve_the_parent_validator_keys() {
    let (_directory, state, writer, task, config) = start_store().await;
    for quorum in [
        None,
        Some(PendingValidatorQuorum { quorum: 3, activation_height: 2.into() }),
        Some(PendingValidatorQuorum { quorum: 2, activation_height: 3.into() }),
    ] {
        let inputs = BlockBuilder::get_block_inputs(
            &state,
            SelectedBlock {
                block_number: BlockNumber::from(1),
                batches: Vec::new(),
            },
        )
        .await
        .unwrap();
        let proposal = BlockBuilder::propose_block(inputs, quorum).await.unwrap();
        let (header, _) = proposal.proposed_block.into_header_and_body().unwrap();
        assert_eq!(header.validator_config(), &config);
    }
    let inputs = BlockBuilder::get_block_inputs(
        &state,
        SelectedBlock {
            block_number: BlockNumber::from(1),
            batches: Vec::new(),
        },
    )
    .await
    .unwrap();
    assert!(
        BlockBuilder::propose_block(
            inputs,
            Some(PendingValidatorQuorum { quorum: 2, activation_height: 2.into() })
        )
        .await
        .is_err()
    );
    writer.stop(task).await;
}
