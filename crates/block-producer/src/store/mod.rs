use std::num::NonZeroU32;

use miden_node_proto::domain::sequencer::TransactionInputs;
use miden_node_store::State;
use miden_node_tracing::{debug, miden_instrument};
use miden_protocol::note::NoteHeader;
use miden_protocol::transaction::ProvenTransaction;

use crate::errors::{MempoolSubmissionError, StateConflict};
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
    err(level = "debug"),
    fields(
        transaction.id = proven_tx.id()
    ),
)]
pub async fn get_tx_inputs(
    state: &State,
    proven_tx: &ProvenTransaction,
) -> Result<TransactionInputs, MempoolSubmissionError> {
    let nullifiers = proven_tx.nullifiers().collect::<Vec<_>>();
    let unauthenticated_note_ids =
        proven_tx.unauthenticated_notes().map(NoteHeader::id).collect::<Vec<_>>();

    let account_id = proven_tx.account_id();
    let creates_account = proven_tx.account_update().initial_state_commitment().is_empty();
    let tx_inputs = state
        .read(move |view| -> Result<_, MempoolSubmissionError> {
            let commitment = view.snapshot.account_tree.get_latest_commitment(account_id);
            // An empty commitment means this account ID is not registered on-chain, so the
            // transaction would create it. Account ID prefixes must be unique across registered
            // accounts; a collision rejects the transaction regardless of its nullifiers or notes.
            if commitment.is_empty()
                && view
                    .snapshot
                    .account_tree
                    .contains_account_id_prefix_in_latest(account_id.prefix())
            {
                debug_assert!(
                    creates_account,
                    "account id prefix uniqueness should not be validated unless transaction creates a new account"
                );
                return Err(MempoolSubmissionError::AuthenticationFailed(
                    StateConflict::AccountIdPrefixAlreadyExists(account_id),
                ));
            }

            let nullifiers = nullifiers
                .into_iter()
                .map(|nullifier| {
                    let block_num = view.snapshot.nullifier_tree.get_block_num(&nullifier);
                    (nullifier, block_num.and_then(|number| NonZeroU32::new(number.as_u32())))
                })
                .collect();
            let found_unauthenticated_notes =
                view.tx.select_existing_note_ids(&unauthenticated_note_ids)?;

            Ok(TransactionInputs {
                account_id,
                account_commitment: (!commitment.is_empty()).then_some(commitment),
                nullifiers,
                found_unauthenticated_notes,
                current_block_height: view.snapshot.block_num,
            })
        })
        .await?;

    debug!(target: LOG_TARGET, "Transaction inputs loaded");
    Ok(tx_inputs)
}

#[cfg(test)]
mod tests;
