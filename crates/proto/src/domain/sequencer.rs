//! Domain types for the sequencer API.

use std::collections::{HashMap, HashSet};
use std::fmt::{Display, Formatter};
use std::num::NonZeroU32;
use std::sync::Arc;

use miden_node_utils::formatting::format_opt;
use miden_protobuf::{BuildUnchecked, Verify, VerifyWith};
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::batch::ProposedBatch;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::Nullifier;
use miden_protocol::transaction::{ProvenTransaction, TransactionId, TxAccountUpdate};
use thiserror::Error;

use crate::errors::{ConversionError, ConversionResultExt};
use crate::generated::sequencer;

impl VerifyWith<u32> for sequencer::DecodedAuthenticatedTransactionBatch {
    type Verified = (ProposedBatch, Vec<TransactionInputs>);
    type Error = ConversionError;

    /// Verify transaction proofs at the supplied security level and decode store inputs. The caller
    /// must trust the sender's store authentication data. The mempool checks dependencies,
    /// conflicts, and expiration.
    fn verify_with(self, security_level: u32) -> Result<Self::Verified, Self::Error> {
        let batch = self.proposed_batch.verify_with(security_level).context("proposed_batch")?;
        if batch.transactions().len() != self.auth_inputs.len() {
            return Err(ConversionError::message(format!(
                "authentication input count {} does not match transaction count {}",
                self.auth_inputs.len(),
                batch.transactions().len()
            )));
        }
        let inputs = self
            .auth_inputs
            .into_iter()
            .enumerate()
            .map(|(index, inputs)| inputs.verify().with_context(|| format!("auth_inputs[{index}]")))
            .collect::<Result<Vec<_>, _>>()?;
        Ok((batch, inputs))
    }
}

/// Information needed from the store to verify a transaction.
#[derive(Debug)]
pub struct TransactionInputs {
    /// The account ID.
    pub account_id: AccountId,
    /// The account commitment in the store.
    pub account_commitment: Option<Word>,
    /// Map each nullifier to the block that consumed the note, or `None` if it is unspent.
    ///
    /// The wire format uses 0 to encode `None`.
    pub nullifiers: HashMap<Nullifier, Option<NonZeroU32>>,
    /// Unauthenticated note commitments that are present in the store.
    ///
    /// These notes were committed after the transaction was created.
    pub found_unauthenticated_notes: HashSet<Word>,
    /// The current block height.
    pub current_block_height: BlockNumber,
}

impl From<TransactionInputs> for sequencer::AuthInputs {
    fn from(value: TransactionInputs) -> Self {
        Self {
            account_id: Some(value.account_id.into()),
            account_commitment: value.account_commitment.map(Into::into),
            nullifiers: value
                .nullifiers
                .into_iter()
                .map(|(nullifier, block_num)| sequencer::NullifierRecord {
                    nullifier: Some(nullifier.as_word().into()),
                    block_num: block_num.map_or(0, NonZeroU32::get),
                })
                .collect(),
            found_unauthenticated_notes: value
                .found_unauthenticated_notes
                .into_iter()
                .map(Into::into)
                .collect(),
            current_block_height: value.current_block_height.as_u32(),
        }
    }
}

impl Verify for sequencer::DecodedAuthInputs {
    type Verified = TransactionInputs;
    type Error = ConversionError;

    fn verify(self) -> Result<Self::Verified, Self::Error> {
        let account_id = self.account_id.verify().context("account_id")?;
        let nullifiers = self
            .nullifiers
            .into_iter()
            .map(|record| {
                (Nullifier::from_raw(record.nullifier), NonZeroU32::new(record.block_num))
            })
            .collect();
        Ok(TransactionInputs {
            account_id,
            account_commitment: self.account_commitment,
            nullifiers,
            found_unauthenticated_notes: self.found_unauthenticated_notes.into_iter().collect(),
            current_block_height: self.current_block_height.into(),
        })
    }
}

impl Display for TransactionInputs {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let nullifiers = self
            .nullifiers
            .iter()
            .map(|(k, v)| format!("{k}: {}", format_opt(v.as_ref())))
            .collect::<Vec<_>>()
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

/// The transaction consumes notes that are already spent in the supplied store inputs.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("nullifiers already exist: {spent_nullifiers:?}")]
pub struct TransactionAuthenticationError {
    pub spent_nullifiers: Vec<Nullifier>,
}

/// A transaction with store authentication data supplied by a trusted caller.
///
/// The caller must verify the proof. [`Self::new_unchecked`] checks the supplied nullifier results
/// and records which input notes the store has committed. Protobuf conversion trusts the sender's
/// authentication data. The mempool resolves remaining note and account dependencies and checks
/// conflicts and expiration.
///
/// Clones share the transaction through an [`Arc`].
///
/// Authentication is valid only at the recorded chain height.
#[derive(Clone, Debug, PartialEq)]
pub struct AuthenticatedTransaction {
    inner: Arc<ProvenTransaction>,
    /// The account state from the store [inputs](TransactionInputs).
    ///
    /// Pending transactions can cause this to differ from the initial transaction state.
    store_account_state: Option<Word>,
    /// Input notes that were unauthenticated when the transaction was proven. Store inputs or
    /// committed mempool history have since authenticated these notes.
    notes_authenticated_by_store: HashSet<Word>,
    /// The chain height at authentication.
    ///
    /// FIXME: Include the block commitment to identify the exact state used for authentication.
    authentication_height: BlockNumber,
}

impl AuthenticatedTransaction {
    /// Check that the transaction nullifiers are unspent in the supplied store inputs.
    ///
    /// The caller must verify the transaction proof and supply trusted store inputs.
    ///
    /// # Errors
    ///
    /// Return an error if the inputs mark any transaction nullifier as spent.
    pub fn new_unchecked(
        tx: Arc<ProvenTransaction>,
        inputs: TransactionInputs,
    ) -> Result<AuthenticatedTransaction, TransactionAuthenticationError> {
        // FIXME: Check that the inputs belong to this account and cover every transaction
        // nullifier. A missing nullifier result currently counts as unspent.
        let nullifiers_already_spent = tx
            .nullifiers()
            .filter(|nullifier| inputs.nullifiers.get(nullifier).copied().flatten().is_some())
            .collect::<Vec<_>>();
        if !nullifiers_already_spent.is_empty() {
            return Err(TransactionAuthenticationError {
                spent_nullifiers: nullifiers_already_spent,
            });
        }

        Ok(AuthenticatedTransaction {
            inner: tx,
            notes_authenticated_by_store: inputs.found_unauthenticated_notes,
            authentication_height: inputs.current_block_height,
            store_account_state: inputs.account_commitment,
        })
    }

    pub fn id(&self) -> TransactionId {
        self.inner.id()
    }

    pub fn account_id(&self) -> AccountId {
        self.inner.account_id()
    }

    pub fn account_update(&self) -> &TxAccountUpdate {
        self.inner.account_update()
    }

    pub fn store_account_state(&self) -> Option<Word> {
        self.store_account_state
    }

    pub fn authentication_height(&self) -> BlockNumber {
        self.authentication_height
    }

    pub fn nullifiers(&self) -> impl Iterator<Item = Nullifier> + '_ {
        self.inner.nullifiers()
    }

    pub fn output_note_ids(&self) -> impl Iterator<Item = Word> + '_ {
        self.inner.output_notes().iter().map(|n| n.id().as_word())
    }

    pub fn output_note_count(&self) -> usize {
        self.inner.output_notes().num_notes()
    }

    pub fn input_note_count(&self) -> usize {
        self.inner.input_notes().num_notes() as usize
    }

    pub fn reference_block(&self) -> (BlockNumber, Word) {
        (self.inner.ref_block_num(), self.inner.ref_block_commitment())
    }

    /// Return input note IDs that neither the transaction nor committed state authenticates.
    pub fn unauthenticated_note_ids(&self) -> impl Iterator<Item = Word> + '_ {
        self.inner
            .unauthenticated_notes()
            .map(|h| h.id().as_word())
            .filter(|commitment| !self.notes_authenticated_by_store.contains(commitment))
    }

    /// Mark these note commitments as authenticated by committed state. The caller must check that
    /// the notes belong to committed state.
    pub fn mark_notes_authenticated(&mut self, notes: impl IntoIterator<Item = Word>) {
        self.notes_authenticated_by_store.extend(notes);
    }

    pub fn proven_transaction(&self) -> Arc<ProvenTransaction> {
        Arc::clone(&self.inner)
    }

    pub fn expires_at(&self) -> BlockNumber {
        self.inner.expiration_block_num()
    }

    pub fn raw_proven_transaction(&self) -> &ProvenTransaction {
        &self.inner
    }
}

// PROTO CONVERSIONS
// ================================================================================================

impl From<AuthenticatedTransaction> for sequencer::AuthenticatedTransaction {
    fn from(value: AuthenticatedTransaction) -> Self {
        Self {
            transaction: Some(value.inner.as_ref().into()),
            store_account_state: value.store_account_state.map(Into::into),
            notes_authenticated_by_store: value
                .notes_authenticated_by_store
                .into_iter()
                .map(Into::into)
                .collect(),
            authentication_height: value.authentication_height.as_u32(),
        }
    }
}

impl BuildUnchecked for sequencer::DecodedAuthenticatedTransaction {
    type Output = AuthenticatedTransaction;
    type Error = ConversionError;

    /// Construct a transaction authenticated by a trusted sequencer client. The caller must ensure
    /// that the client verified and authenticated the transaction.
    fn build_unchecked(self) -> Result<Self::Output, Self::Error> {
        // SAFETY: The caller must trust the sender to verify the transaction proof and store
        // authentication data. This constructor does not establish that trust.
        let inner = self.transaction.build_unchecked().context("transaction")?;
        Ok(AuthenticatedTransaction {
            inner: Arc::new(inner),
            store_account_state: self.store_account_state,
            notes_authenticated_by_store: self.notes_authenticated_by_store.into_iter().collect(),
            authentication_height: self.authentication_height.into(),
        })
    }
}
