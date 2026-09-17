use std::num::NonZeroU32;

use miden_node_proto::domain::sequencer::TransactionInputs;
use miden_node_store::state::{State, TransactionInputs as StoreTransactionInputs};
use miden_node_tracing::{debug, miden_instrument};
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::transaction::ProvenTransaction;

use crate::errors::StoreError;
use crate::{COMPONENT, LOG_TARGET};

/// Authenticates a proven transaction against the store, returning the [`TransactionInputs`]
/// needed to admit it to the mempool.
///
/// This reads the committed state relevant to the transaction: the account's current commitment,
/// the consumption status of each of the transaction's nullifiers, and which of its unauthenticated
/// input notes have since been committed. The result is captured at the store's current committed
/// chain tip.
///
/// # Errors
///
/// Returns an error if the store query fails, or if the transaction creates a new account whose ID
/// prefix already exists in the store.
#[miden_instrument(
    target = COMPONENT,
    name = "store.state.get_tx_inputs",
    err,
    fields(
        transaction.id = proven_tx.id()
    ),
)]
pub async fn get_tx_inputs(
    state: &State,
    proven_tx: &ProvenTransaction,
) -> Result<TransactionInputs, StoreError> {
    let nullifiers = proven_tx.nullifiers().collect::<Vec<_>>();
    let unauthenticated_note_commitments =
        proven_tx.unauthenticated_notes().map(|header| header.id().as_word()).collect();

    let (current_block_height, store_inputs) = state
        .with_view(async |view| {
            view.get_transaction_inputs(
                proven_tx.account_id(),
                &nullifiers,
                unauthenticated_note_commitments,
            )
            .await
            .map(|inputs| (view.tip(), inputs))
            .map_err(StoreError::GetTransactionInputsFailed)
        })
        .await?;

    if !store_inputs.new_account_id_prefix_is_unique.unwrap_or(true) {
        debug_assert!(
            proven_tx.account_update().initial_state_commitment().is_empty(),
            "account id prefix uniqueness should not be validated unless transaction creates a new account"
        );
        return Err(StoreError::DuplicateAccountIdPrefix(proven_tx.account_id()));
    }

    let tx_inputs = from_store_inputs(proven_tx.account_id(), store_inputs, *current_block_height);

    debug!(target: LOG_TARGET, "Transaction inputs loaded");

    Ok(tx_inputs)
}

fn from_store_inputs(
    account_id: AccountId,
    inputs: StoreTransactionInputs,
    current_block_height: BlockNumber,
) -> TransactionInputs {
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

    TransactionInputs {
        account_id,
        account_commitment,
        nullifiers,
        found_unauthenticated_notes: inputs.found_unauthenticated_notes,
        current_block_height,
    }
}
