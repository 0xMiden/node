//! Transaction input query for the block producer's transaction validation.

use std::collections::HashSet;
use std::ops::ControlFlow;

use miden_node_tracing::miden_instrument;
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::note::{NoteId, Nullifier};

use super::StateView;
use crate::COMPONENT;
use crate::db::NullifierInfo;
use crate::errors::DatabaseError;

/// Store-level inputs for validating a proven transaction.
#[derive(Debug, Default)]
pub struct TransactionInputs {
    pub account_commitment: Word,
    pub nullifiers: Vec<NullifierInfo>,
    pub found_unauthenticated_notes: HashSet<NoteId>,
    pub new_account_id_prefix_is_unique: Option<bool>,
}

impl StateView {
    /// Returns data needed by the block producer to verify transaction validity.
    #[miden_instrument(
        target = COMPONENT,
        fields(
            account.id = account_id,
            note.nullifiers = nullifiers,
        ),
    )]
    pub async fn get_transaction_inputs(
        &self,
        account_id: AccountId,
        nullifiers: &[Nullifier],
        unauthenticated_note_ids: Vec<NoteId>,
    ) -> Result<TransactionInputs, DatabaseError> {
        let tree_inputs = self.with_inner_read_blocking(|inner| {
            let account_commitment = inner.account_tree.get_latest_commitment(account_id);

            let new_account_id_prefix_is_unique = if account_commitment.is_empty() {
                Some(!inner.account_tree.contains_account_id_prefix_in_latest(account_id.prefix()))
            } else {
                None
            };

            // Non-unique account Id prefixes for new accounts are not allowed, so the transaction
            // cannot be valid and the response is already complete.
            if let Some(false) = new_account_id_prefix_is_unique {
                return ControlFlow::Break(TransactionInputs {
                    new_account_id_prefix_is_unique,
                    ..Default::default()
                });
            }

            let nullifiers = nullifiers
                .iter()
                .map(|nullifier| NullifierInfo {
                    nullifier: *nullifier,
                    block_num: inner.nullifier_tree.get_block_num(nullifier).unwrap_or_default(),
                })
                .collect();

            ControlFlow::Continue((account_commitment, nullifiers, new_account_id_prefix_is_unique))
        });
        // `Break` carries a complete response (duplicate account ID prefix), so it is returned
        // as-is without the note lookup below; `Continue` carries the tree reads needed to build
        // the full response.
        let (account_commitment, nullifiers, new_account_id_prefix_is_unique) = match tree_inputs {
            ControlFlow::Continue(inputs) => inputs,
            ControlFlow::Break(response) => return Ok(response),
        };

        // Scope the note lookup by the view's tip so the result is consistent with the tree reads
        // above: mid-apply, the DB may already contain notes from a block the snapshot does not
        // include yet.
        let found_unauthenticated_notes =
            self.db.select_existing_note_ids(unauthenticated_note_ids, self.tip()).await?;

        Ok(TransactionInputs {
            account_commitment,
            nullifiers,
            found_unauthenticated_notes,
            new_account_id_prefix_is_unique,
        })
    }
}
