use std::collections::{HashMap, HashSet};
use std::fmt::{Display, Formatter};
use std::num::NonZeroU32;

use itertools::Itertools;
use miden_node_store::state::{Finality, State, TransactionInputs as StoreTransactionInputs};
use miden_node_utils::formatting::format_opt;
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::Nullifier;
use miden_protocol::transaction::ProvenTransaction;
use tracing::{info, instrument};

use crate::COMPONENT;
use crate::errors::StoreError;

// TRANSACTION INPUTS
// ================================================================================================

/// Information needed from the store to verify a transaction.
#[derive(Debug)]
pub struct TransactionInputs {
    /// Account ID
    pub account_id: AccountId,
    /// The account commitment in the store corresponding to tx's account ID
    pub account_commitment: Option<Word>,
    /// Maps each consumed notes' nullifier to block number, where the note is consumed.
    ///
    /// We use `NonZeroU32` as the wire format uses 0 to encode none.
    pub nullifiers: HashMap<Nullifier, Option<NonZeroU32>>,
    /// Unauthenticated note commitments which are present in the store.
    ///
    /// These are notes which were committed _after_ the transaction was created.
    pub found_unauthenticated_notes: HashSet<Word>,
    /// The current block height.
    pub current_block_height: BlockNumber,
}

impl TransactionInputs {
    fn from_store_inputs(
        account_id: AccountId,
        inputs: StoreTransactionInputs,
        current_block_height: BlockNumber,
    ) -> Self {
        let account_commitment = if inputs.account_commitment == Word::empty() {
            None
        } else {
            Some(inputs.account_commitment)
        };

        let nullifiers = inputs
            .nullifiers
            .into_iter()
            .map(|nullifier| (nullifier.nullifier, NonZeroU32::new(nullifier.block_num.as_u32())))
            .collect();

        Self {
            account_id,
            account_commitment,
            nullifiers,
            found_unauthenticated_notes: inputs.found_unauthenticated_notes,
            current_block_height,
        }
    }
}

impl Display for TransactionInputs {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let nullifiers = self
            .nullifiers
            .iter()
            .map(|(k, v)| format!("{k}: {}", format_opt(v.as_ref())))
            .join(", ");

        let nullifiers = if nullifiers.is_empty() {
            "None".to_owned()
        } else {
            format!("{{ {nullifiers} }}")
        };

        f.write_fmt(format_args!(
            "{{ account_id: {}, account_commitment: {}, nullifiers: {} }}",
            self.account_id,
            format_opt(self.account_commitment.as_ref()),
            nullifiers
        ))
    }
}

// STORE STATE
// ================================================================================================

#[instrument(target = COMPONENT, name = "store.state.get_tx_inputs", skip_all, err)]
pub async fn get_tx_inputs(
    state: &State,
    proven_tx: &ProvenTransaction,
) -> Result<TransactionInputs, StoreError> {
    info!(target: COMPONENT, tx_id = %proven_tx.id().to_hex());

    let nullifiers = proven_tx.nullifiers().collect::<Vec<_>>();
    let unauthenticated_note_commitments =
        proven_tx.unauthenticated_notes().map(|header| header.id().as_word()).collect();

    let store_inputs = state
        .get_transaction_inputs(
            proven_tx.account_id(),
            &nullifiers,
            unauthenticated_note_commitments,
        )
        .await
        .map_err(StoreError::GetTransactionInputsFailed)?;

    if !store_inputs.new_account_id_prefix_is_unique.unwrap_or(true) {
        debug_assert!(
            proven_tx.account_update().initial_state_commitment().is_empty(),
            "account id prefix uniqueness should not be validated unless transaction creates a new account"
        );
        return Err(StoreError::DuplicateAccountIdPrefix(proven_tx.account_id()));
    }

    let current_block_height = state.chain_tip(Finality::Committed).await;
    let tx_inputs = TransactionInputs::from_store_inputs(
        proven_tx.account_id(),
        store_inputs,
        current_block_height,
    );

    Ok(tx_inputs)
}
