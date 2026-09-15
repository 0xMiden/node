//! Real transaction proofs for submission tests.

use miden_processor::{ExecutionOptions, FastProcessor};
use miden_protocol::MIN_PROOF_SECURITY_LEVEL;
use miden_protocol::account::AccountUpdateDetails;
use miden_protocol::block::{BlockSignatures, SignedBlock};
use miden_protocol::note::NoteType;
use miden_protocol::transaction::{
    ProvenTransaction,
    TransactionInputs,
    TransactionKernel,
    TransactionVerifier,
    TxAccountUpdate,
};
use miden_protocol::vm::{ExecutionProof, PrecompileStatus};
use miden_testing::{Auth, MockChainBuilder};
use miden_tx::{
    AccountProcedureIndexMap,
    Prover,
    ScriptMastForestStore,
    TransactionMastStore,
    TransactionProverHost,
};
use tokio::sync::OnceCell;

/// A valid deferred transaction and the data needed to submit it.
pub struct DeferredTransactionFixture {
    pub genesis: SignedBlock,
    pub transaction: ProvenTransaction,
    pub inputs: TransactionInputs,
}

/// Builds one ECDSA transaction proof per test process.
pub async fn deferred_transaction_fixture() -> &'static DeferredTransactionFixture {
    static FIXTURE: OnceCell<DeferredTransactionFixture> = OnceCell::const_new();
    FIXTURE
        .get_or_init(|| async {
            let mut builder = MockChainBuilder::new().verification_base_fee(0);
            let account = builder.add_existing_wallet(Auth::basic_ecdsa()).unwrap();
            let note = builder.add_p2any_note(account.id(), NoteType::Private, []).unwrap();
            let chain = builder.build().unwrap();
            let (header, body, ..) = chain.latest_block().into_parts();
            let genesis =
                SignedBlock::new_unchecked(header, body, BlockSignatures::new(Vec::new()).unwrap());
            let executed = Box::pin(
                chain
                    .build_transaction(account.id())
                    .authenticated_input_note(note.id())
                    .build()
                    .unwrap()
                    .execute(),
            )
            .await
            .unwrap();
            let inputs = executed.tx_inputs().clone();
            let (stack_inputs, advice_inputs) = TransactionKernel::prepare_inputs(&inputs);
            let mast_store = TransactionMastStore::new();
            mast_store.load_account_code(inputs.account().code());
            let scripts = ScriptMastForestStore::new(
                inputs.tx_script(),
                inputs.input_notes().iter().map(|note| note.note().script()),
            );
            let indices = AccountProcedureIndexMap::new([inputs.account().code()]);
            let mut host = TransactionProverHost::new(
                inputs.account(),
                inputs.input_notes().clone(),
                inputs.collect_block_commitments(),
                &mast_store,
                scripts,
                indices,
            );
            // Keep the precompile witness in the proof for the batch prover.
            let witness = FastProcessor::new_with_options(
                stack_inputs,
                advice_inputs.into_advice_inputs(),
                ExecutionOptions::default(),
            )
            .unwrap()
            .execute_for_proving_sync(&TransactionKernel::main(), &mut host)
            .unwrap();
            let proof = Prover::default().prove(witness).unwrap();
            let account_update = TxAccountUpdate::new(
                executed.account_id(),
                executed.initial_account().initial_commitment(),
                executed.final_account().to_commitment(),
                executed.account_patch().to_commitment(),
                AccountUpdateDetails::Public(executed.account_patch().clone()),
            )
            .unwrap();
            let transaction = ProvenTransaction::new(
                account_update,
                executed.input_notes().iter(),
                executed
                    .output_notes()
                    .iter()
                    .cloned()
                    .map(|note| note.into_output_note().unwrap()),
                executed.block_header().block_num(),
                executed.block_header().commitment(),
                executed.expiration_block_num(),
                proof,
            )
            .unwrap();
            let outcome =
                TransactionVerifier::new(MIN_PROOF_SECURITY_LEVEL).verify(&transaction).unwrap();
            assert!(!outcome.is_complete());
            DeferredTransactionFixture { genesis, transaction, inputs }
        })
        .await
}

/// Removes the deferred witness without changing the VM proof or its committed root.
#[expect(
    clippy::default_trait_access,
    reason = "The protocol does not re-export DeferredStateWire."
)]
pub fn proof_with_missing_deferred_witness(transaction: &ProvenTransaction) -> ExecutionProof {
    assert!(!transaction.proof().is_complete());
    ExecutionProof::from_parts(
        transaction.proof().compatibility().clone(),
        transaction.proof().vm().clone(),
        PrecompileStatus::Deferred(Default::default()),
    )
}
