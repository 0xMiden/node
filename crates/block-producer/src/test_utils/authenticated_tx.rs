use std::collections::HashSet;
use std::sync::Arc;

use miden_node_proto::domain::sequencer::{AuthenticatedTransaction, TransactionInputs};
use miden_protocol::Word;
use miden_protocol::block::BlockNumber;
use miden_protocol::transaction::ProvenTransaction;

/// Build a fixture with matching account state and unspent nullifiers.
pub struct MockAuthenticatedTxBuilder {
    transaction: ProvenTransaction,
    inputs: TransactionInputs,
}

impl MockAuthenticatedTxBuilder {
    pub fn new(transaction: ProvenTransaction) -> Self {
        let account_commitment = match transaction.account_update().initial_state_commitment() {
            zero if zero == Word::empty() => None,
            non_zero => Some(non_zero),
        };
        let inputs = TransactionInputs {
            account_id: transaction.account_id(),
            account_commitment,
            nullifiers: transaction.nullifiers().map(|nullifier| (nullifier, None)).collect(),
            found_unauthenticated_notes: HashSet::default(),
            current_block_height: BlockNumber::GENESIS,
        };
        Self { transaction, inputs }
    }

    #[must_use]
    pub fn with_authentication_height(mut self, height: BlockNumber) -> Self {
        self.inputs.current_block_height = height;
        self
    }

    #[must_use]
    pub fn with_store_state(mut self, state: Word) -> Self {
        self.inputs.account_commitment = Some(state);
        self
    }

    pub fn build(self) -> AuthenticatedTransaction {
        AuthenticatedTransaction::new_unchecked(Arc::new(self.transaction), self.inputs).unwrap()
    }
}
