use std::collections::BTreeMap;

use miden_node_proto::generated::validator::api_server;
use miden_node_proto::generated::{self as proto};
use miden_node_store::GenesisState;
use miden_node_utils::fee::test_fee_params;
use miden_protocol::block::{BlockHeader, BlockInputs, ProposedBlock};
use miden_protocol::testing::random_secret_key::random_secret_key;
use miden_protocol::transaction::PartialBlockchain;
use miden_protocol::utils::Serializable;

use super::ValidatorServer;
use crate::ValidatorSigner;
use crate::db::{load, load_chain_tip, upsert_block_header};

// TEST HELPERS
// ================================================================================================

/// Test harness that wraps a [`ValidatorServer`] and tracks the chain MMR state needed to
/// construct valid [`ProposedBlock`]s.
struct TestValidator {
    server: ValidatorServer,
    chain: PartialBlockchain,
    chain_tip: BlockHeader,
}

impl TestValidator {
    /// Creates a [`ValidatorServer`] bootstrapped with a random genesis block.
    async fn new() -> Self {
        let signer = ValidatorSigner::new_local(random_secret_key());

        let genesis_state = GenesisState::new(vec![], test_fee_params(), 1, 0, random_secret_key());
        let genesis_block = genesis_state.into_block().await.unwrap();
        let genesis_header = genesis_block.inner().header().clone();

        let dir = tempfile::tempdir().unwrap();
        let db = load(dir.path().join("validator.sqlite3")).await.unwrap();

        db.transact("upsert_genesis", {
            let h = genesis_header.clone();
            move |conn| upsert_block_header(conn, &h)
        })
        .await
        .unwrap();

        Self {
            server: ValidatorServer::new(signer, db),
            chain: PartialBlockchain::default(),
            chain_tip: genesis_header,
        }
    }

    /// Builds an empty [`ProposedBlock`] extending the current chain tip.
    fn propose_empty_block(&self) -> ProposedBlock {
        empty_block(&self.chain_tip, &self.chain)
    }

    /// Calls `sign_block` on the validator server.
    async fn call_sign_block(
        &self,
        proposed_block: &ProposedBlock,
    ) -> Result<tonic::Response<proto::blockchain::BlockSignature>, tonic::Status> {
        let request = tonic::Request::new(proto::blockchain::ProposedBlock {
            proposed_block: proposed_block.to_bytes(),
        });
        api_server::Api::sign_block(&self.server, request).await
    }

    /// Returns a reference to the validator's database.
    fn db(&self) -> &miden_node_db::Db {
        &self.server.db
    }

    /// Returns a reference to the validator's signer.
    fn signer(&self) -> &ValidatorSigner {
        &self.server.signer
    }

    /// Loads the current chain tip from the validator's database.
    async fn load_chain_tip(&self) -> BlockHeader {
        self.server
            .db
            .query("load_chain_tip", load_chain_tip)
            .await
            .unwrap()
            .expect("chain tip should exist")
    }

    /// Builds, submits, and applies an empty block, advancing the chain tip.
    ///
    /// Panics if the block is rejected.
    async fn apply_empty_block(&mut self) {
        let proposed = self.propose_empty_block();
        self.call_sign_block(&proposed).await.unwrap();
        let (header, _) = proposed.into_header_and_body().unwrap();
        // Advance our local chain state to match what the server now has.
        self.chain.add_block(&self.chain_tip, false);
        self.chain_tip = header;
    }
}

/// Builds an empty [`ProposedBlock`] that extends the given parent block header using the
/// provided partial blockchain state.
fn empty_block(parent_header: &BlockHeader, chain: &PartialBlockchain) -> ProposedBlock {
    let block_inputs = BlockInputs::new(
        parent_header.clone(),
        chain.clone(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
    );
    ProposedBlock::new(block_inputs, vec![]).unwrap()
}

// TESTS
// ================================================================================================

/// An empty block at chain tip + 1 with the correct previous block commitment should be accepted.
#[tokio::test]
async fn chain_tip_plus_one_succeeds() {
    let tv = TestValidator::new().await;

    let proposed = tv.propose_empty_block();
    let result = tv.call_sign_block(&proposed).await;

    assert!(result.is_ok(), "chain tip + 1 should succeed, got: {:?}", result.err());
}

/// A replacement block at the same height as the current chain tip should be accepted.
#[tokio::test]
async fn chain_tip_replacement_succeeds() {
    let mut tv = TestValidator::new().await;

    // The genesis block can never be replaced, so we advance the chain
    // to block 1, which we can then replace.
    let genesis_header = tv.chain_tip.clone();
    let chain_at_genesis = tv.chain.clone();
    tv.apply_empty_block().await;
    let original_header = tv.chain_tip.clone();

    // Submit a different block at the same height (block 1), which is a replacement.
    // Use an explicit timestamp far in the future to ensure the replacement block differs.
    let block_inputs = BlockInputs::new(
        genesis_header.clone(),
        chain_at_genesis.clone(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
    );
    let far_future_timestamp = genesis_header.timestamp() + 1_000_000;
    let replacement = ProposedBlock::new_at(block_inputs, vec![], far_future_timestamp).unwrap();
    let (replacement_header, _) = replacement.clone().into_header_and_body().unwrap();

    assert_eq!(replacement_header.block_num(), original_header.block_num());
    assert_ne!(
        replacement_header.commitment(),
        original_header.commitment(),
        "replacement block should differ from the original"
    );

    let result = tv.call_sign_block(&replacement).await;
    assert!(result.is_ok(), "chain tip replacement should succeed, got: {:?}", result.err());

    // Verify that the chain tip in the database is now the replacement block, not the original.
    let new_chain_tip = tv.load_chain_tip().await;
    assert_eq!(
        new_chain_tip.commitment(),
        replacement_header.commitment(),
        "chain tip should be the replacement block"
    );
    assert_ne!(
        new_chain_tip.commitment(),
        original_header.commitment(),
        "chain tip should no longer be the original block"
    );
}

/// A block at chain tip + 2 (skipping a block number) should be rejected.
#[tokio::test]
async fn chain_tip_plus_two_rejected() {
    let mut tv = TestValidator::new().await;

    // Apply block 1.
    tv.apply_empty_block().await;

    // Build block 2 locally without applying it, then build block 3 on top.
    let block_2 = tv.propose_empty_block();
    let (block_2_header, _) = block_2.into_header_and_body().unwrap();
    let mut chain_after_1 = tv.chain.clone();
    chain_after_1.add_block(&tv.chain_tip, false);
    let block_3 = empty_block(&block_2_header, &chain_after_1);

    let result = tv.call_sign_block(&block_3).await;
    assert!(result.is_err(), "chain tip + 2 should be rejected");
    let status = result.unwrap_err();
    assert!(
        status.message().contains("block number mismatch"),
        "expected block number mismatch error, got: {}",
        status.message()
    );
}

/// A block at chain tip - 1 (behind the tip) should be rejected.
#[tokio::test]
async fn chain_tip_minus_one_rejected() {
    let mut tv = TestValidator::new().await;

    // Save genesis state.
    let genesis_header = tv.chain_tip.clone();
    let chain_at_genesis = tv.chain.clone();

    // Advance the chain to block 2.
    tv.apply_empty_block().await;
    tv.apply_empty_block().await;

    // Try to submit a block at height 1 (chain tip - 1). This is neither a replacement
    // (which would need to match tip height 2) nor the next block (which would be 3).
    let stale_block = empty_block(&genesis_header, &chain_at_genesis);

    let result = tv.call_sign_block(&stale_block).await;
    assert!(result.is_err(), "chain tip - 1 should be rejected");
    let status = result.unwrap_err();
    assert!(
        status.message().contains("block number mismatch"),
        "expected block number mismatch error, got: {}",
        status.message()
    );
}

/// A block with the wrong previous block commitment should be rejected.
#[tokio::test]
async fn commitment_mismatch_rejected() {
    let tv = TestValidator::new().await;

    // Build a valid ProposedBlock on a *different* genesis so its prev_block_commitment
    // won't match the validator's actual chain tip.
    let other_genesis_state =
        GenesisState::new(vec![], test_fee_params(), 1, 1, random_secret_key());
    let other_genesis_block = other_genesis_state.into_block().await.unwrap();
    let other_genesis_header = other_genesis_block.inner().header().clone();
    let mismatched_block = empty_block(&other_genesis_header, &PartialBlockchain::default());

    let result = tv.call_sign_block(&mismatched_block).await;
    assert!(result.is_err(), "commitment mismatch should be rejected");
    let status = result.unwrap_err();
    assert!(
        status.message().contains("previous block commitment"),
        "expected commitment mismatch error, got: {}",
        status.message()
    );
}

/// An empty block (no transactions, no batches) should be accepted.
#[tokio::test]
async fn empty_block_succeeds() {
    let tv = TestValidator::new().await;

    let proposed = tv.propose_empty_block();
    assert_eq!(proposed.transactions().count(), 0, "block should have no transactions");

    let result = tv.call_sign_block(&proposed).await;
    assert!(result.is_ok(), "empty block should succeed, got: {:?}", result.err());
}

/// A block containing transactions that were not previously validated should be rejected.
#[tokio::test]
async fn unknown_transactions_rejected() {
    use miden_protocol::Word;
    use miden_protocol::asset::FungibleAsset;
    use miden_protocol::batch::{BatchAccountUpdate, BatchId, ProvenBatch};
    use miden_protocol::block::BlockNumber;
    use miden_protocol::testing::account_id::ACCOUNT_ID_SENDER;
    use miden_protocol::transaction::{
        InputNoteCommitment,
        InputNotes,
        OrderedTransactionHeaders,
        TransactionHeader,
    };

    use crate::block_validation::{BlockValidationError, validate_block};

    let tv = TestValidator::new().await;
    let genesis_header = tv.chain_tip.clone();

    // Build a dummy transaction header with a transaction ID that has NOT been
    // submitted through `submit_proven_transaction`.
    let account_id = ACCOUNT_ID_SENDER.try_into().unwrap();
    let fee = FungibleAsset::new(test_fee_params().native_asset_id(), 0).unwrap();
    let tx_header = TransactionHeader::new(
        account_id,
        Word::default(),
        Word::default(),
        InputNotes::<InputNoteCommitment>::default(),
        vec![],
        fee,
    );
    let tx_id = tx_header.id();

    // Build a ProvenBatch containing this transaction.
    let batch = ProvenBatch::new(
        BatchId::from_ids(std::iter::once((tx_id, account_id))),
        genesis_header.commitment(),
        BlockNumber::GENESIS,
        BTreeMap::from([(
            account_id,
            BatchAccountUpdate::new_unchecked(
                account_id,
                Word::default(),
                Word::default(),
                miden_protocol::account::delta::AccountUpdateDetails::Private,
            ),
        )]),
        InputNotes::default(),
        vec![],
        BlockNumber::MAX,
        OrderedTransactionHeaders::new_unchecked(vec![tx_header]),
    )
    .unwrap();

    // Build a ProposedBlock containing the batch with the unknown transaction.
    let block_inputs = BlockInputs::new(
        genesis_header.clone(),
        PartialBlockchain::default(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
    );
    let proposed = ProposedBlock::new(block_inputs, vec![batch]).unwrap();

    let result = validate_block(proposed, tv.signer(), tv.db(), genesis_header).await;
    assert!(result.is_err(), "block with unknown transactions should be rejected");
    match result.unwrap_err() {
        BlockValidationError::UnvalidatedTransactions(ids) => {
            assert_eq!(ids, vec![tx_id], "should report the unknown transaction ID");
        },
        other => panic!("expected UnvalidatedTransactions error, got: {other}"),
    }
}

/// After replacing the chain tip, a new block built against the pre-replacement tip should be
/// rejected because its previous block commitment no longer matches.
#[tokio::test]
async fn new_block_after_replacement_with_stale_commitment_rejected() {
    let mut tv = TestValidator::new().await;

    // Advance to block 1 and save the state needed to build on top of it.
    let genesis_header = tv.chain_tip.clone();
    let chain_at_genesis = tv.chain.clone();
    tv.apply_empty_block().await;
    let original_block_1_header = tv.chain_tip.clone();
    let chain_after_block_1 = tv.chain.clone();

    // Replace block 1 with a different block at the same height.
    let block_inputs = BlockInputs::new(
        genesis_header.clone(),
        chain_at_genesis.clone(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
    );
    let far_future_timestamp = genesis_header.timestamp() + 1_000_000;
    let replacement = ProposedBlock::new_at(block_inputs, vec![], far_future_timestamp).unwrap();
    let (replacement_header, _) = replacement.clone().into_header_and_body().unwrap();
    assert_ne!(
        replacement_header.commitment(),
        original_block_1_header.commitment(),
        "replacement block should differ from the original"
    );
    tv.call_sign_block(&replacement).await.unwrap();

    // Now try to submit block 2 built on top of the *original* block 1.
    // Its prev_block_commitment points to the old block 1, not the replacement.
    let stale_block_2 = empty_block(&original_block_1_header, &chain_after_block_1);

    let result = tv.call_sign_block(&stale_block_2).await;
    assert!(
        result.is_err(),
        "block with stale commitment after replacement should be rejected"
    );
    let status = result.unwrap_err();
    assert!(
        status.message().contains("previous block commitment"),
        "expected commitment mismatch error, got: {}",
        status.message()
    );
}

/// Verify that `validate_block` rejects blocks with a non-sequential block number.
#[tokio::test]
async fn validate_block_number_mismatch() {
    use crate::block_validation::{BlockValidationError, validate_block};

    let mut tv = TestValidator::new().await;

    // Advance to block 1.
    tv.apply_empty_block().await;
    let block_1_header = tv.chain_tip.clone();

    // Build block 2 and 3 locally, then try to submit block 3 with chain_tip = block 1.
    let mut chain = tv.chain.clone();
    let block_2 = empty_block(&block_1_header, &chain);
    let (block_2_header, _) = block_2.into_header_and_body().unwrap();

    chain.add_block(&block_1_header, false);
    let block_3 = empty_block(&block_2_header, &chain);

    let result = validate_block(block_3, tv.signer(), tv.db(), block_1_header).await;
    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), BlockValidationError::BlockNumberMismatch { .. }),
        "expected BlockNumberMismatch error"
    );
}
