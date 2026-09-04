use std::collections::BTreeMap;

use miden_node_proto::domain::encryption::{
    TransactionEncryptionScheme,
    TrustedTransactionEncryptionState,
    transaction_inputs_associated_data,
    verify_transaction_encryption_key,
};
use miden_node_proto::generated::{self as proto};
use miden_node_proto::server::validator_api;
use miden_node_store::{BlockStore, GenesisState};
use miden_node_utils::fee::test_fee_params;
use miden_protocol::Word;
use miden_protocol::account::AccountUpdateDetails;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::block::{BlockHeader, BlockInputs, BlockNumber, ProposedBlock, ValidatorKeys};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey;
use miden_protocol::crypto::dsa::eddsa_25519_sha512::KeyExchangeKey;
use miden_protocol::note::NoteType;
use miden_protocol::testing::account_id::{ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET, ACCOUNT_ID_SENDER};
use miden_protocol::testing::random_secret_key::random_secret_key;
use miden_protocol::transaction::{
    InputNoteCommitment,
    OutputNote,
    PartialBlockchain,
    ProvenTransaction,
    TransactionId,
    TransactionInputs,
    TxAccountUpdate,
};
use miden_protocol::vm::ExecutionProof;
use miden_testing::{Auth, MockChainBuilder};
use miden_tx::LocalTransactionProver;
use miden_tx::utils::serde::{Deserializable, Serializable};
use tokio::sync::OnceCell;

use super::{ValidatorError, ValidatorService};
use crate::db::{ValidatorDbWriter, setup};
use crate::metrics::InitialMetrics;
use crate::storage_key::tests::operator_keys;
use crate::{
    LocalX25519TransactionInputDecrypter,
    PrivateRecordSealer,
    TransactionInputDecrypter,
    ValidatorSigner,
};

// TEST HELPERS
// ================================================================================================

/// The shared transaction encryption secret provisioned to every test validator.
const TEST_ENCRYPTION_SECRET: [u8; 32] = [3u8; 32];

/// Creates a [`LocalX25519TransactionInputDecrypter`] from the shared test secret, modelling the
/// identically provisioned encryption key of a validator in the set.
fn test_decrypter() -> LocalX25519TransactionInputDecrypter {
    let key = KeyExchangeKey::read_from_bytes(&TEST_ENCRYPTION_SECRET)
        .expect("test secret should be a valid key exchange key");
    LocalX25519TransactionInputDecrypter::new(key)
}

/// Test harness that wraps a [`Validator`] and tracks the chain MMR state needed to construct valid
/// [`ProposedBlock`]s.
struct TestValidator {
    server: ValidatorService,
    chain: PartialBlockchain,
    chain_tip: BlockHeader,
    // Keeps the database's temp directory alive for the validator's lifetime: the reader pool opens
    // connections lazily, so the file must still exist when the first read runs.
    _temp_dir: tempfile::TempDir,
}

impl TestValidator {
    /// Creates a correctly configured [`ValidatorService`]: the validator signs blocks with the
    /// same key that is designated as the `validator_key` in the genesis block.
    async fn new() -> Self {
        let key = random_secret_key();
        let signer = ValidatorSigner::new_local(key.clone());
        let (temp_dir, db, block_store, genesis_header) = setup_db_with_genesis(&key).await;

        Self {
            server: ValidatorService::new(
                signer,
                db,
                std::sync::Arc::new(test_decrypter()),
                PrivateRecordSealer::from_operator_key(&operator_keys().remove(0)),
                block_store,
                InitialMetrics::default(),
            )
            .await
            .unwrap(),
            chain: PartialBlockchain::default(),
            chain_tip: genesis_header,
            _temp_dir: temp_dir,
        }
    }

    /// Builds an empty [`ProposedBlock`] extending the current chain tip.
    fn propose_empty_block(&self) -> ProposedBlock {
        empty_block(&self.chain_tip, &self.chain)
    }

    /// Calls `submit_proven_transaction` on the validator server.
    async fn call_submit_proven_transaction(
        &self,
        tx: &ProvenTransaction,
        sealed: proto::transaction::SealedTransactionInputs,
    ) -> Result<(), tonic::Status> {
        let request = tonic::Request::new(proto::transaction::ProvenTransaction {
            transaction: tx.to_bytes(),
            sealed_transaction_inputs: Some(sealed),
        });
        validator_api::SubmitProvenTransaction::full(&self.server, request).await
    }

    /// Seals `plaintext` exactly as a well-behaved client would: against the key this validator
    /// serves, bound to `tx_id` and this network's genesis commitment.
    fn seal(
        &self,
        tx_id: TransactionId,
        plaintext: &[u8],
    ) -> proto::transaction::SealedTransactionInputs {
        let key = &self.server.encryption_key_info;
        let associated_data = transaction_inputs_associated_data(
            key.scheme.as_u32(),
            &key.key_id,
            self.server.genesis_commitment,
            tx_id,
        );
        let sealed = test_decrypter()
            .sealing_key()
            .seal_bytes_with_associated_data(&mut rand::rng(), plaintext, &associated_data)
            .expect("sealing should succeed");

        proto::transaction::SealedTransactionInputs {
            key_id: key.key_id.clone(),
            ciphertext: sealed.to_bytes(),
        }
    }

    /// Calls `sign_block` on the validator server.
    async fn call_sign_block(
        &self,
        proposed_block: &ProposedBlock,
    ) -> Result<proto::blockchain::SignBlockResponse, tonic::Status> {
        let request = tonic::Request::new(proto::blockchain::ProposedBlock {
            proposed_block: proposed_block.to_bytes(),
        });
        validator_api::SignBlock::full(&self.server, request).await
    }

    /// Opens a block subscription starting from `block_from`.
    async fn call_block_subscription(
        &self,
        block_from: u32,
    ) -> <ValidatorService as proto::server::validator_api::BlockSubscription>::ItemStream {
        self.try_call_block_subscription(block_from)
            .await
            .expect("subscription should open")
    }

    /// Opens a block subscription starting from `block_from`, returning the raw result so callers
    /// can assert on rejection.
    async fn try_call_block_subscription(
        &self,
        block_from: u32,
    ) -> Result<
        <ValidatorService as proto::server::validator_api::BlockSubscription>::ItemStream,
        tonic::Status,
    > {
        let request =
            tonic::Request::new(proto::validator::BlockSubscriptionRequest { block_from });
        validator_api::BlockSubscription::full(&self.server, request).await
    }

    /// Calls the `status` endpoint on the validator server.
    async fn call_status(&self) -> proto::validator::ValidatorStatus {
        validator_api::Status::full(&self.server, tonic::Request::new(()))
            .await
            .expect("status should always be available")
    }

    /// Returns whether `tx_id` has a validated transaction marker.
    async fn transaction_exists(&self, tx_id: TransactionId) -> bool {
        self.server.db.transaction_exists(tx_id).await.unwrap()
    }

    /// Returns the persisted validated transaction count.
    async fn validated_transaction_count(&self) -> i64 {
        self.server.db.count_validated_transactions().await.unwrap()
    }

    /// Asserts that a rejected transaction did not change either validated count.
    async fn assert_transaction_absent(&self, tx_id: TransactionId, expected_count: i64) {
        assert!(!self.transaction_exists(tx_id).await);
        assert_eq!(self.validated_transaction_count().await, expected_count);
        assert_eq!(
            self.call_status().await.validated_transactions_count,
            u64::try_from(expected_count).unwrap(),
        );
    }

    /// Calls the `get_transaction_encryption_key` endpoint on the validator server.
    async fn call_get_transaction_encryption_key(
        &self,
    ) -> proto::transaction::TransactionEncryptionKey {
        validator_api::GetTransactionEncryptionKey::full(&self.server, tonic::Request::new(()))
            .await
            .expect("encryption key should always be available")
    }

    /// Asserts that opening a backup subscription is rejected with `resource_exhausted`. The
    /// success type ([`Self::ItemStream`]) is not `Debug`, so we match rather than `expect_err`.
    async fn assert_backup_rejected(&self, block_from: u32) {
        match self.try_call_block_subscription(block_from).await {
            Ok(_) => panic!("backup subscription should have been rejected"),
            Err(status) => {
                assert_eq!(status.code(), tonic::Code::ResourceExhausted, "got: {status:?}");
            },
        }
    }

    /// Loads the current chain tip from the validator's database.
    async fn load_chain_tip(&self) -> BlockHeader {
        self.server.db.load_chain_tip().await.unwrap().expect("chain tip should exist")
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

/// Creates a validator database seeded with a genesis block whose `validator_key` is the public key
/// of `key`. Returns the database handle and the genesis block header.
async fn setup_db_with_genesis(
    key: &SigningKey,
) -> (tempfile::TempDir, ValidatorDbWriter, BlockStore, BlockHeader) {
    let genesis_state = GenesisState::new(
        vec![],
        test_fee_params(),
        1,
        0,
        ValidatorKeys::new(vec![key.public_key()]).unwrap(),
    );
    let genesis_block = genesis_state.into_block().unwrap();
    let genesis_header = genesis_block.inner().header().clone();

    let dir = tempfile::tempdir().unwrap();
    let db = setup(dir.path().join("validator.sqlite3")).await.unwrap();
    let block_store =
        BlockStore::bootstrap(dir.path().join("blocks").clone(), &genesis_block).unwrap();

    db.upsert_block_header(genesis_header.clone()).await.unwrap();

    (dir, db, block_store, genesis_header)
}

/// Builds an empty [`ProposedBlock`] that extends the given parent block header using the provided
/// partial blockchain state.
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

/// Builds a syntactically valid [`ProvenTransaction`] with a dummy proof.
fn dummy_proven_tx(seed: u8) -> ProvenTransaction {
    let account_update = TxAccountUpdate::new(
        miden_protocol::testing::account_id::ACCOUNT_ID_PRIVATE_SENDER
            .try_into()
            .unwrap(),
        Word::empty(),
        Word::from([u32::from(seed), 0, 0, 0]),
        Word::empty(),
        AccountUpdateDetails::Private,
    )
    .unwrap();

    // The account state changes, which is what keeps this from being rejected as an empty
    // transaction; no input or output notes are needed.
    ProvenTransaction::new(
        account_update,
        Vec::<InputNoteCommitment>::new(),
        Vec::<OutputNote>::new(),
        BlockNumber::GENESIS,
        Word::empty(),
        BlockNumber::from(u32::from(seed) + 1),
        ExecutionProof::new_dummy(),
    )
    .unwrap()
}

/// A proven transaction and alternate inputs used to reach each validation stage.
struct ProvenTransactionFixture {
    transaction: ProvenTransaction,
    inputs: TransactionInputs,
    execution_failure_inputs: TransactionInputs,
    mismatch_inputs: TransactionInputs,
}

/// Builds one real proof and two alternate, well-formed input sets.
async fn proven_transaction_fixture() -> &'static ProvenTransactionFixture {
    static FIXTURE: OnceCell<ProvenTransactionFixture> = OnceCell::const_new();

    FIXTURE
        .get_or_init(|| async {
            let mut chain_builder = MockChainBuilder::new();
            let auth = Auth::BasicAuth {
                auth_scheme: AuthScheme::Falcon512Poseidon2,
            };
            let account_a = chain_builder.add_existing_wallet(auth.clone()).unwrap();
            let account_b = chain_builder.add_existing_wallet(auth).unwrap();
            assert_ne!(account_a.id(), account_b.id());

            let asset: Asset =
                FungibleAsset::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into().unwrap(), 100)
                    .unwrap()
                    .into();
            let note_a = chain_builder
                .add_p2id_note(
                    ACCOUNT_ID_SENDER.try_into().unwrap(),
                    account_a.id(),
                    &[asset],
                    NoteType::Private,
                )
                .unwrap();
            let note_b = chain_builder
                .add_p2id_note(
                    ACCOUNT_ID_SENDER.try_into().unwrap(),
                    account_b.id(),
                    &[asset],
                    NoteType::Private,
                )
                .unwrap();
            let chain = chain_builder.build().unwrap();

            let context_a = chain
                .build_transaction(account_a.id())
                .authenticated_input_note(note_a.id())
                .build()
                .unwrap();
            let executed_a = Box::pin(context_a.execute()).await.unwrap();
            let inputs = executed_a.tx_inputs().clone();
            let transaction = LocalTransactionProver::default().prove(inputs.clone()).unwrap();

            let context_b = chain
                .build_transaction(account_b.id())
                .authenticated_input_note(note_b.id())
                .build()
                .unwrap();
            let mismatch_inputs = Box::pin(context_b.execute()).await.unwrap().tx_inputs().clone();
            let mut execution_failure_inputs = inputs.clone();
            execution_failure_inputs.set_input_notes(vec![note_b]);

            ProvenTransactionFixture {
                transaction,
                inputs,
                execution_failure_inputs,
                mismatch_inputs,
            }
        })
        .await
}

// TESTS
// ================================================================================================

/// A validator whose signing key does not match the `validator_key` designated by the chain
/// (carried forward from genesis) must fail to start, rather than coming up and silently producing
/// signatures that the block producer cannot verify.
#[tokio::test]
async fn signing_key_mismatch_rejected() {
    // Seed a database whose genesis designates `genesis_key` as the validator key.
    let genesis_key = random_secret_key();
    let (_temp_dir, db, block_store, genesis_header) = setup_db_with_genesis(&genesis_key).await;

    // Start a validator with a different key, modelling a validator configured with the wrong key.
    let rogue_signer = ValidatorSigner::new_local(random_secret_key());
    assert!(
        !genesis_header.validator_keys().as_keys().contains(&rogue_signer.public_key()),
        "test requires a signing key that is not a member of the genesis validator set",
    );

    let result = ValidatorService::new(
        rogue_signer,
        db,
        std::sync::Arc::new(test_decrypter()),
        PrivateRecordSealer::from_operator_key(&operator_keys().remove(0)),
        block_store,
        InitialMetrics::default(),
    )
    .await;
    assert!(
        matches!(result, Err(ValidatorError::ValidatorKeyNotInSet { .. })),
        "expected ValidatorKeyNotInSet error",
    );
}

/// The `SignBlock` response reports the commitment of the block the validator signed, and it
/// matches the commitment the caller derives from the same proposed block. This lets the block
/// producer detect a block-hash mismatch between itself and the validator.
#[tokio::test]
async fn sign_block_returns_signed_commitment() {
    let tv = TestValidator::new().await;

    let proposed = tv.propose_empty_block();
    let response = tv.call_sign_block(&proposed).await.expect("block should be signed");

    let (header, _) = proposed.into_header_and_body().unwrap();
    let returned: Word = response
        .block_commitment
        .expect("response should carry the signed commitment")
        .try_into()
        .unwrap();
    assert_eq!(
        returned,
        header.commitment(),
        "returned commitment must match the proposed block's commitment",
    );
}

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

    // The genesis block can never be replaced, so we advance the chain to block 1, which we can
    // then replace.
    let genesis_header = tv.chain_tip.clone();
    let chain_at_genesis = tv.chain.clone();
    tv.apply_empty_block().await;
    let original_header = tv.chain_tip.clone();

    // Submit a different block at the same height (block 1), which is a replacement. Use an
    // explicit timestamp far in the future to ensure the replacement block differs.
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

    // Try to submit a block at height 1 (chain tip - 1). This is neither a replacement (which would
    // need to match tip height 2) nor the next block (which would be 3).
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

    // Build a valid ProposedBlock on a *different* genesis so its prev_block_commitment won't match
    // the validator's actual chain tip.
    let other_genesis_signer = random_secret_key();
    let other_genesis_state = GenesisState::new(
        vec![],
        test_fee_params(),
        1,
        1,
        ValidatorKeys::new(vec![other_genesis_signer.public_key()]).unwrap(),
    );
    let other_genesis_block = other_genesis_state.into_block().unwrap();
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

/// A replacement block (same height as chain tip) with the wrong parent commitment should be
/// rejected.
#[tokio::test]
async fn replacement_commitment_mismatch_rejected() {
    let mut tv = TestValidator::new().await;

    // Advance past genesis so we have a replaceable block.
    tv.apply_empty_block().await;

    // Build a replacement block at the same height but using a *different* genesis so its
    // prev_block_commitment won't match the validator's actual parent of the chain tip.
    let other_genesis_signer = random_secret_key();
    let other_genesis_state = GenesisState::new(
        vec![],
        test_fee_params(),
        1,
        1,
        ValidatorKeys::new(vec![other_genesis_signer.public_key()]).unwrap(),
    );
    let other_genesis_block = other_genesis_state.into_block().unwrap();
    let other_genesis_header = other_genesis_block.inner().header().clone();
    let mismatched_replacement = empty_block(&other_genesis_header, &PartialBlockchain::default());

    let result = tv.call_sign_block(&mismatched_replacement).await;
    assert!(result.is_err(), "replacement with mismatched commitment should be rejected");
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
    use miden_protocol::batch::{BatchAccountUpdate, BatchId, ProvenBatch};
    use miden_protocol::block::BlockNumber;
    use miden_protocol::testing::account_id::ACCOUNT_ID_SENDER;
    use miden_protocol::transaction::{
        InputNoteCommitment,
        InputNotes,
        OrderedTransactionHeaders,
        TransactionHeader,
    };
    use miden_protocol::vm::ExecutionProof;

    let tv = TestValidator::new().await;
    let genesis_header = tv.chain_tip.clone();

    // Build a dummy transaction header with a transaction ID that has NOT been submitted through
    // `submit_proven_transaction`.
    let account_id = ACCOUNT_ID_SENDER.try_into().unwrap();
    let tx_header = TransactionHeader::new(
        account_id,
        Word::default(),
        Word::default(),
        InputNotes::<InputNoteCommitment>::default(),
        vec![],
    );
    let tx_id = tx_header.id();

    // Build a ProvenBatch containing this transaction.
    let batch = ProvenBatch::new_unchecked(
        BatchId::from_ids(std::iter::once((tx_id, account_id))),
        genesis_header.commitment(),
        BlockNumber::GENESIS,
        BTreeMap::from([(
            account_id,
            BatchAccountUpdate::new_unchecked(
                account_id,
                Word::default(),
                Word::default(),
                miden_protocol::account::AccountUpdateDetails::Private,
            ),
        )]),
        InputNotes::default(),
        vec![],
        BlockNumber::MAX,
        OrderedTransactionHeaders::new_unchecked(vec![tx_header]),
        ExecutionProof::new_dummy(),
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

    let result = tv.server.validate_block(proposed, genesis_header).await;
    assert!(result.is_err(), "block with unknown transactions should be rejected");
    match result.unwrap_err() {
        ValidatorError::UnvalidatedTransactions(ids) => {
            assert_eq!(ids, vec![tx_id], "should report the unknown transaction ID");
        },
        other => panic!("expected UnvalidatedTransactions error, got: {other}"),
    }
}

/// Signing a block records which block includes each of its transactions, so the administration API
/// can filter validated transactions by block range.
#[tokio::test]
async fn sign_block_links_transactions_to_the_signed_block() {
    use miden_protocol::batch::{BatchAccountUpdate, BatchId, ProvenBatch};
    use miden_protocol::transaction::{InputNotes, OrderedTransactionHeaders, TransactionHeader};
    use rand_chacha_03::rand_core::SeedableRng;

    use crate::db::ListTransactionsParams;
    use crate::private_record::test_private_record_sealer;
    use crate::{PrivateRecordChainId, PrivateRecordContext, PrivateRecordId, StorageKeyEpoch};

    let tv = TestValidator::new().await;
    let genesis_header = tv.chain_tip.clone();

    // Build a dummy transaction and record it as validated, as `submit_proven_transaction` would.
    let account_id = ACCOUNT_ID_SENDER.try_into().unwrap();
    let tx_header = TransactionHeader::new(
        account_id,
        Word::default(),
        Word::default(),
        InputNotes::<InputNoteCommitment>::default(),
        vec![],
    );
    let tx_id = tx_header.id();
    let key_epoch = StorageKeyEpoch::new([2; 32]);
    let record = test_private_record_sealer(key_epoch, [4; 32])
        .seal(
            &mut rand_chacha_03::ChaCha20Rng::from_seed([1; 32]),
            PrivateRecordId::new(tx_id, &random_secret_key().public_key()),
            PrivateRecordContext::new(PrivateRecordChainId::new([1; 32]), key_epoch, tx_id),
            b"private transaction inputs",
        )
        .unwrap();
    tv.server.db.insert_validated_private_transaction(record).await.unwrap();

    // Build a block containing the transaction and have the validator sign it.
    let batch = ProvenBatch::new_unchecked(
        BatchId::from_ids(std::iter::once((tx_id, account_id))),
        genesis_header.commitment(),
        BlockNumber::GENESIS,
        BTreeMap::from([(
            account_id,
            BatchAccountUpdate::new_unchecked(
                account_id,
                Word::default(),
                Word::default(),
                AccountUpdateDetails::Private,
            ),
        )]),
        InputNotes::default(),
        vec![],
        BlockNumber::MAX,
        OrderedTransactionHeaders::new_unchecked(vec![tx_header]),
        ExecutionProof::new_dummy(),
    )
    .unwrap();
    let block_inputs = BlockInputs::new(
        genesis_header.clone(),
        PartialBlockchain::default(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
    );
    let proposed = ProposedBlock::new(block_inputs, vec![batch]).unwrap();
    tv.call_sign_block(&proposed).await.expect("block should be signed");

    // The signed block links its transaction to block 1 at index 0.
    let listed = tv
        .server
        .db
        .list_validated_transactions(ListTransactionsParams {
            start: Some((BlockNumber::from(1u32), 0)),
            block_to: Some(BlockNumber::from(1u32)),
            limit: 10,
        })
        .await
        .unwrap();
    assert_eq!(
        listed
            .iter()
            .map(|item| (item.transaction_id, item.block_num, item.block_tx_index))
            .collect::<Vec<_>>(),
        vec![(tx_id, BlockNumber::from(1u32), 0)],
        "the signed block's transaction should be linked to block 1 at index 0"
    );
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

    // Now try to submit block 2 built on top of the *original* block 1. Its prev_block_commitment
    // points to the old block 1, not the replacement.
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

    let result = tv.server.validate_block(block_3, block_1_header).await;
    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), ValidatorError::BlockNumberMismatch { .. }),
        "expected BlockNumberMismatch error"
    );
}

/// A block subscription replays the backed-up blocks from the requested height. While the
/// subscription is live it holds the exclusive backup lock, so signing is frozen for its duration
/// and no further blocks can be produced or streamed.
#[tokio::test]
async fn block_subscription_replays_then_freezes_signing() {
    use std::time::Duration;

    use miden_protocol::block::SignedBlock;
    use miden_tx::utils::serde::Deserializable;
    use tokio_stream::StreamExt;

    let mut tv = TestValidator::new().await;

    // Sign blocks 1 and 2 so the validator backs them up to its block store.
    tv.apply_empty_block().await;
    tv.apply_empty_block().await;

    // Subscribe from the first signed block and confirm the backed-up blocks are replayed in order.
    let mut stream = tv.call_block_subscription(1).await;
    for expected in 1..=2 {
        let response = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("replayed block should arrive promptly")
            .expect("stream should not end")
            .expect("stream item should not be an error");
        let block = SignedBlock::read_from_bytes(&response.block).expect("valid signed block");
        assert_eq!(block.header().block_num().as_u32(), expected);
        assert_eq!(response.committed_chain_tip, 2);
    }

    // The live subscription holds the backup lock, so no new block can be signed while it is open.
    // The validator therefore cannot produce a block to stream, and signing is rejected until the
    // subscriber disconnects.
    let proposed = tv.propose_empty_block();
    let status = tv
        .call_sign_block(&proposed)
        .await
        .expect_err("sign_block must be rejected while a backup subscription is live");
    assert_eq!(status.code(), tonic::Code::ResourceExhausted, "got: {status:?}");

    // Once the subscriber disconnects, signing resumes.
    drop(stream);
    tv.call_sign_block(&proposed)
        .await
        .expect("sign_block should succeed once the subscription is dropped");
}

// SERVE LOCK TESTS
// ================================================================================================
//
// A backup subscription holds the exclusive write side of `serve_lock` for the lifetime of the
// returned stream; every other RPC takes the read side. The two are therefore mutually exclusive:
// a backup cannot start while requests are in flight, and requests are rejected while a backup is
// streaming. Both sides fail fast with `resource_exhausted` rather than blocking.

/// While a backup subscription is streaming, `sign_block` is rejected, and it succeeds again once
/// the subscription is dropped and the lock released.
#[tokio::test]
async fn backup_stream_blocks_sign_block_until_dropped() {
    let mut tv = TestValidator::new().await;
    tv.apply_empty_block().await;

    // Open a backup subscription; the returned stream holds the exclusive lock.
    let stream = tv.call_block_subscription(1).await;

    let proposed = tv.propose_empty_block();
    let status = tv
        .call_sign_block(&proposed)
        .await
        .expect_err("sign_block must be rejected while a backup is streaming");
    assert_eq!(status.code(), tonic::Code::ResourceExhausted, "got: {status:?}");

    // Dropping the subscription releases the lock, so the same request now succeeds.
    drop(stream);
    tv.call_sign_block(&proposed)
        .await
        .expect("sign_block should succeed once the backup stream is dropped");
}

/// Unlike other RPCs, `status` stays available during a backup and reports `BACKUP` instead of
/// `OK`, reverting to `OK` once the subscription is dropped.
#[tokio::test]
async fn status_reports_backup_while_streaming() {
    let mut tv = TestValidator::new().await;
    tv.apply_empty_block().await;

    assert_eq!(tv.call_status().await.status, "OK");

    let stream = tv.call_block_subscription(1).await;
    assert_eq!(
        tv.call_status().await.status,
        "BACKUP",
        "status must report BACKUP while a backup is streaming",
    );

    drop(stream);
    assert_eq!(
        tv.call_status().await.status,
        "OK",
        "status must revert to OK once the backup stream is dropped",
    );
}

/// A backup subscription cannot start while another request holds the read side of the lock,
/// modelling an in-flight RPC. Once that reader is released, the backup opens successfully.
#[tokio::test]
async fn in_flight_request_blocks_backup() {
    let tv = TestValidator::new().await;

    // Simulate an in-flight RPC by holding the read side of the lock, exactly as the RPC handlers
    // do for their duration.
    let read_guard = tv.server.serve_lock.try_read().expect("read side should be available");

    tv.assert_backup_rejected(0).await;

    // Releasing the reader lets a backup start.
    drop(read_guard);
    let _stream = tv.call_block_subscription(0).await;
}

/// Only one backup subscription can run at a time: opening a second while the first is live is
/// rejected.
#[tokio::test]
async fn concurrent_backups_rejected() {
    let tv = TestValidator::new().await;

    let first = tv.call_block_subscription(0).await;

    tv.assert_backup_rejected(0).await;

    // The slot frees up once the first subscription is dropped.
    drop(first);
    let _stream = tv.call_block_subscription(0).await;
}

/// Ordinary requests share the read side of the lock and so run concurrently with one another; only
/// a backup is exclusive.
#[tokio::test]
async fn requests_run_concurrently() {
    let tv = TestValidator::new().await;

    // Multiple readers may hold the lock at once, so requests are not serialized against each
    // other.
    let first = tv.server.serve_lock.try_read().expect("first reader should acquire");
    let second = tv
        .server
        .serve_lock
        .try_read()
        .expect("second reader should acquire concurrently");

    // A backup is still excluded while any reader is held.
    tv.assert_backup_rejected(0).await;

    drop(first);
    drop(second);
}

// TRANSACTION ENCRYPTION KEY
// ================================================================================================

/// The endpoint returns the shared encryption key attested by this validator's own signing key. The
/// signature verifies over a commitment recomputed from the response fields and the chain's genesis
/// commitment, so a client needs nothing beyond the response and the chain data it already trusts.
#[tokio::test]
async fn transaction_encryption_key_is_attested() {
    let tv = TestValidator::new().await;
    // The chain has not advanced, so the chain tip is the genesis header.
    let genesis = tv.chain_tip.commitment();
    let response = tv.call_get_transaction_encryption_key().await;

    let info = test_decrypter().encryption_key().await.expect("key info should be available");
    let scheme = TransactionEncryptionScheme::try_from(response.scheme).unwrap();
    assert_eq!(scheme, info.scheme);
    assert_eq!(response.key_id, info.key_id);
    assert_eq!(response.public_key, info.public_key);

    let [attestation] = response.attestations.as_slice() else {
        panic!("response must carry exactly the serving validator's attestation");
    };
    assert_eq!(
        attestation.validator_public_key,
        tv.server.signer.public_key().to_bytes(),
        "attestation must identify the serving validator",
    );
    let trusted_keys = [tv.server.signer.public_key()];
    let verified = verify_transaction_encryption_key(
        response,
        TrustedTransactionEncryptionState::new(genesis, &trusted_keys),
    )
    .expect("attestation must verify against this validator's signing key");
    assert_eq!(verified.info(), &info);
}

/// Two validators provisioned with the same shared encryption secret but distinct signing keys
/// return identical public key material with different signatures.
#[tokio::test]
async fn shared_key_is_attested_per_validator() {
    let tv_a = TestValidator::new().await;
    let tv_b = TestValidator::new().await;

    let response_a = tv_a.call_get_transaction_encryption_key().await;
    let response_b = tv_b.call_get_transaction_encryption_key().await;

    assert_eq!(response_a.scheme, response_b.scheme);
    assert_eq!(response_a.key_id, response_b.key_id);
    assert_eq!(response_a.public_key, response_b.public_key);
    assert_ne!(
        response_a.attestations[0].signature, response_b.attestations[0].signature,
        "each validator must attest with its own signing key",
    );
}

/// The attestation signature must not survive tampering with any field of the response, nor a
/// swapped chain.
#[tokio::test]
async fn tampered_attestation_fails_verification() {
    let tv = TestValidator::new().await;
    let genesis = tv.chain_tip.commitment();
    let response = tv.call_get_transaction_encryption_key().await;
    let trusted_keys = [tv.server.signer.public_key()];
    let trusted = TrustedTransactionEncryptionState::new(genesis, &trusted_keys);

    let mut changed_scheme = response.clone();
    changed_scheme.scheme += 1;
    let mut changed_key_id = response.clone();
    changed_key_id.key_id[0] ^= 0x01;
    let mut changed_public_key = response.clone();
    changed_public_key.public_key =
        KeyExchangeKey::read_from_bytes(&[4u8; 32]).unwrap().public_key().to_bytes();
    let mut injected_next_key = response.clone();
    injected_next_key.next_key = Some(proto::transaction::NextTransactionEncryptionKey {
        scheme: response.scheme,
        key_id: response.key_id.clone(),
        public_key: response.public_key.clone(),
        rotation_block_num: 100,
    });

    for tampered in [changed_scheme, changed_key_id, changed_public_key, injected_next_key] {
        assert!(
            verify_transaction_encryption_key(tampered, trusted).is_err(),
            "attestation must not verify over tampered fields",
        );
    }

    let tampered_genesis = Word::try_from([9u64, 9, 9, 9]).unwrap();
    assert!(
        verify_transaction_encryption_key(
            response,
            TrustedTransactionEncryptionState::new(tampered_genesis, &trusted_keys),
        )
        .is_err(),
        "attestation must not verify for another network",
    );
}

/// A client can reconstruct the sealing key from the response fields and seal a payload that any
/// validator holding the shared secret can unseal. Unsealing must reject mismatched associated
/// data.
#[tokio::test]
async fn response_key_seals_for_the_validator_set() {
    use miden_protocol::crypto::dsa::eddsa_25519_sha512::PublicKey as EncryptionPublicKey;
    use miden_protocol::crypto::ies::SealingKey;

    let tv = TestValidator::new().await;
    let response = tv.call_get_transaction_encryption_key().await;

    let public_key = EncryptionPublicKey::read_from_bytes(&response.public_key)
        .expect("response public key should deserialize");
    let sealing_key = SealingKey::X25519XChaCha20Poly1305(public_key);

    let mut rng = rand::rng();
    let plaintext = b"transaction inputs";
    let associated_data = b"scheme|key_id|chain|tx";
    let sealed = sealing_key
        .seal_bytes_with_associated_data(&mut rng, plaintext, associated_data)
        .unwrap();

    let sealed = sealed.to_bytes();
    let opened = test_decrypter()
        .decrypt_transaction_inputs(&sealed, associated_data)
        .await
        .unwrap();
    assert_eq!(opened.as_slice(), plaintext);

    assert!(
        test_decrypter()
            .decrypt_transaction_inputs(&sealed, b"other associated data")
            .await
            .is_err(),
        "decryption must fail under mismatched associated data",
    );
}

/// Like `status`, the encryption key stays available while a backup subscription holds the
/// exclusive serve lock.
#[tokio::test]
async fn encryption_key_available_during_backup() {
    let mut tv = TestValidator::new().await;
    tv.apply_empty_block().await;

    let stream = tv.call_block_subscription(1).await;

    // `call_get_transaction_encryption_key` panics on rejection, so completing proves availability
    // during the backup.
    let response = tv.call_get_transaction_encryption_key().await;
    assert!(!response.public_key.is_empty());

    drop(stream);
}

// SUBMIT PATH: TRANSACTION INPUT SEALING
// ================================================================================================

/// A submission with no encrypted inputs is rejected before validation.
#[tokio::test]
async fn submit_rejects_missing_encrypted_inputs() {
    let tv = TestValidator::new().await;
    let tx = dummy_proven_tx(2);
    let request = tonic::Request::new(proto::transaction::ProvenTransaction {
        transaction: tx.to_bytes(),
        sealed_transaction_inputs: None,
    });

    let status = validator_api::SubmitProvenTransaction::full(&tv.server, request)
        .await
        .unwrap_err();

    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    assert!(status.message().contains("Missing sealed transaction inputs"));
    tv.assert_transaction_absent(tx.id(), 0).await;
}

/// Plaintext transaction inputs must be impossible to submit. This is the central guarantee of the
/// whole change.
#[tokio::test]
async fn submit_rejects_plaintext_inputs() {
    let tv = TestValidator::new().await;
    let tx = dummy_proven_tx(3);
    let sealed = proto::transaction::SealedTransactionInputs {
        key_id: tv.server.encryption_key_info.key_id.clone(),
        ciphertext: b"not a sealed message, just bytes".to_vec(),
    };

    let status = tv.call_submit_proven_transaction(&tx, sealed).await.unwrap_err();

    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    assert!(status.message().contains("unseal"), "got: {}", status.message());
    tv.assert_transaction_absent(tx.id(), 0).await;
}

/// A key id that does not match the validator's earns a distinct, actionable status so a client
/// knows to re-fetch rather than retry the same blob, without disclosing the validator's own key
/// id.
#[tokio::test]
async fn submit_rejects_unknown_key_id() {
    let tv = TestValidator::new().await;
    let tx = dummy_proven_tx(4);
    let mut sealed = tv.seal(tx.id(), b"transaction inputs");
    sealed.key_id = vec![0xAA, 0xBB, 0xCC, 0xDD];

    let status = tv.call_submit_proven_transaction(&tx, sealed).await.unwrap_err();

    assert_eq!(status.code(), tonic::Code::FailedPrecondition);
    assert!(
        status.message().contains("GetTransactionEncryptionKey"),
        "the rejection must tell the client to re-fetch the key, got: {}",
        status.message(),
    );
    // This status reaches the client verbatim through the RPC.
    let own_key_id = hex::encode(&tv.server.encryption_key_info.key_id);
    assert!(
        !status.message().contains(&own_key_id),
        "the rejection must not echo the validator's key id",
    );
    tv.assert_transaction_absent(tx.id(), 0).await;
}

/// The validator enforces the associated data, so a ciphertext captured from one transaction cannot
/// be replayed onto another. Which fields the transcript covers is pinned separately by the golden
/// vector in `miden_node_proto::domain::encryption`.
#[tokio::test]
async fn submit_rejects_inputs_sealed_for_a_different_transaction() {
    let tv = TestValidator::new().await;
    let tx_a = dummy_proven_tx(6);
    let tx_b = dummy_proven_tx(7);
    assert_ne!(tx_a.id(), tx_b.id());

    let sealed_for_a = tv.seal(tx_a.id(), b"transaction inputs");

    let status = tv.call_submit_proven_transaction(&tx_b, sealed_for_a).await.unwrap_err();

    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    assert!(status.message().contains("unseal"), "got: {}", status.message());
    tv.assert_transaction_absent(tx_b.id(), 0).await;
}

/// Correctly sealed inputs get past the unseal and fail later, at deserialization. Without this the
/// tests above would all still pass if the unseal simply always failed.
#[tokio::test]
async fn correctly_sealed_inputs_reach_the_deserialization_stage() {
    let tv = TestValidator::new().await;
    let tx = dummy_proven_tx(10);
    let sealed = tv.seal(tx.id(), b"not really transaction inputs");

    let status = tv.call_submit_proven_transaction(&tx, sealed).await.unwrap_err();

    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    assert!(
        status.message().contains("Invalid transaction inputs"),
        "the unseal should have succeeded and failed at deserialization instead, got: {}",
        status.message(),
    );
    assert!(
        !status.message().contains("unseal"),
        "the unseal must have succeeded, got: {}",
        status.message(),
    );
    tv.assert_transaction_absent(tx.id(), 0).await;
}

/// A failed proof must not store the authenticated transaction inputs.
#[tokio::test]
async fn failed_proof_verification_does_not_store_inputs() {
    let tv = TestValidator::new().await;
    let tx = dummy_proven_tx(11);
    let fixture = proven_transaction_fixture().await;
    let sealed = tv.seal(tx.id(), &fixture.inputs.to_bytes());

    let status = tv.call_submit_proven_transaction(&tx, sealed).await.unwrap_err();

    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    assert!(status.message().contains("proof verification"), "got: {}", status.message());
    tv.assert_transaction_absent(tx.id(), 0).await;
}

/// A transaction that cannot be re-executed must not create a sealed record.
#[tokio::test]
async fn failed_reexecution_does_not_store_inputs() {
    let tv = TestValidator::new().await;
    let fixture = proven_transaction_fixture().await;
    let tx = &fixture.transaction;
    let sealed = tv.seal(tx.id(), &fixture.execution_failure_inputs.to_bytes());

    let status = tv.call_submit_proven_transaction(tx, sealed).await.unwrap_err();

    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    assert!(status.message().contains("re-executed"), "got: {}", status.message());
    tv.assert_transaction_absent(tx.id(), 0).await;
}

/// A successful re-execution with a different header must not create a sealed record.
#[tokio::test]
async fn header_mismatch_does_not_store_inputs() {
    let tv = TestValidator::new().await;
    let fixture = proven_transaction_fixture().await;
    let tx = &fixture.transaction;
    let sealed = tv.seal(tx.id(), &fixture.mismatch_inputs.to_bytes());

    let status = tv.call_submit_proven_transaction(tx, sealed).await.unwrap_err();

    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    assert!(status.message().contains("did not match"), "got: {}", status.message());
    tv.assert_transaction_absent(tx.id(), 0).await;
}

/// A valid submission stores one marker and one protected record.
#[tokio::test]
async fn valid_submission_stores_one_protected_record() {
    let tv = TestValidator::new().await;
    let fixture = proven_transaction_fixture().await;
    let tx = &fixture.transaction;
    let first = tv.seal(tx.id(), &fixture.inputs.to_bytes());
    let second = tv.seal(tx.id(), &fixture.inputs.to_bytes());
    assert_ne!(first.ciphertext, second.ciphertext);

    tv.call_submit_proven_transaction(tx, first.clone()).await.unwrap();
    let transaction_id = tx.id();
    let first_record = tv.server.db.load_private_record(transaction_id).await.unwrap().unwrap();
    tv.call_submit_proven_transaction(tx, second).await.unwrap();

    assert!(tv.transaction_exists(tx.id()).await);
    let stored_record = tv.server.db.load_private_record(transaction_id).await.unwrap().unwrap();
    assert_eq!(stored_record, first_record);
    assert_eq!(tv.validated_transaction_count().await, 1);
    assert_eq!(tv.call_status().await.validated_transactions_count, 1);
}

/// `ValidatorClient::submit_batch` forwards items through this handler one at a time. A failed item
/// must not create its own record when another item in that sequence succeeds.
#[tokio::test]
async fn failed_batch_item_does_not_store_inputs() {
    let tv = TestValidator::new().await;
    let fixture = proven_transaction_fixture().await;
    let valid_tx = &fixture.transaction;
    let rejected_tx = dummy_proven_tx(12);

    tv.call_submit_proven_transaction(valid_tx, tv.seal(valid_tx.id(), &fixture.inputs.to_bytes()))
        .await
        .unwrap();
    let status = tv
        .call_submit_proven_transaction(
            &rejected_tx,
            tv.seal(rejected_tx.id(), &fixture.inputs.to_bytes()),
        )
        .await
        .unwrap_err();

    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    tv.assert_transaction_absent(rejected_tx.id(), 1).await;
    assert!(tv.transaction_exists(valid_tx.id()).await);
}
