use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU32;

use miden_node_proto::domain::sequencer::TransactionInputs;
use miden_node_store::State;
use miden_node_store::read::ReadView;
use miden_node_tracing::{debug, instrument};
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::note::{NoteHeader, NoteId, NoteInclusionProof};
use miden_protocol::transaction::{PartialBlockchain, ProvenTransaction};

use crate::errors::{MempoolSubmissionError, StateConflict, StoreError};

/// Chain data at a reference block that batch and block proposals require.
pub(crate) struct ChainInputs {
    pub reference_block_header: BlockHeader,
    pub partial_blockchain: PartialBlockchain,
    pub note_inclusion_proofs: BTreeMap<NoteId, NoteInclusionProof>,
}

/// Reads the reference block header, inclusion proofs for the notes committed at or before the
/// reference block, and a partial blockchain covering `block_numbers` and the blocks of those
/// notes.
///
/// The partial blockchain describes the chain before the reference block, so it never contains
/// the reference block itself.
pub(crate) fn read_chain_inputs(
    view: &ReadView<'_>,
    reference_block: BlockNumber,
    mut block_numbers: BTreeSet<BlockNumber>,
    note_ids: &BTreeSet<NoteId>,
) -> Result<ChainInputs, StoreError> {
    let chain_tip = view.snapshot.block_num;
    if reference_block > chain_tip {
        return Err(StoreError::ReferenceBlockAfterTip { reference_block, chain_tip });
    }

    let note_inclusion_proofs = view.tx.select_note_inclusion_proofs(note_ids, reference_block)?;
    block_numbers.extend(note_inclusion_proofs.values().map(|proof| proof.location().block_num()));
    if let Some(&block_num) = block_numbers.last()
        && block_num > reference_block
    {
        return Err(StoreError::BlockAfterReferenceBlock { block_num, reference_block });
    }
    block_numbers.remove(&reference_block);

    let partial_mmr = view
        .snapshot
        .blockchain
        .partial_mmr_from_blocks(&block_numbers, reference_block)
        .expect("all requested blocks precede the reference block");
    let headers = view.tx.select_block_headers(block_numbers.iter().copied())?;
    let partial_blockchain = PartialBlockchain::new_unchecked(partial_mmr, headers)
        .expect("the partial MMR and the headers cover the same blocks");
    let reference_block_header = view
        .tx
        .select_block_header(reference_block)?
        .expect("the reference block is at or below the chain tip, so its header is stored");

    Ok(ChainInputs {
        reference_block_header,
        partial_blockchain,
        note_inclusion_proofs,
    })
}

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
#[instrument(
    name = "get_tx_inputs",
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

    debug!("Transaction inputs loaded");
    Ok(tx_inputs)
}

#[cfg(test)]
mod tests;
