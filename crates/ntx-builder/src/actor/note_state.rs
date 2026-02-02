use std::collections::{HashMap, VecDeque};

use miden_node_proto::domain::account::NetworkAccountId;
use miden_node_proto::domain::note::SingleTargetNetworkNote;
use miden_protocol::account::delta::AccountUpdateDetails;
use miden_protocol::account::{Account, AccountDelta, AccountId};
use miden_protocol::block::BlockNumber;
use miden_protocol::note::Nullifier;

use crate::actor::inflight_note::InflightNetworkNote;

// ACCOUNT DELTA TRACKER
// ================================================================================================

/// Tracks committed and inflight account state updates.
#[derive(Clone)]
pub struct AccountDeltaTracker {
    /// The committed account state, if any.
    ///
    /// This may be `None` if the account creation transaction is still inflight.
    committed: Option<Account>,

    /// Inflight account updates in chronological order.
    inflight: VecDeque<Account>,
}

impl AccountDeltaTracker {
    /// Creates a new tracker with the given committed account state.
    pub fn new(account: Account) -> Self {
        Self {
            committed: Some(account),
            inflight: VecDeque::default(),
        }
    }

    /// Appends a delta to the set of inflight account updates.
    pub fn add_delta(&mut self, delta: &AccountDelta) {
        let mut state = self.latest_account();
        state
            .apply_delta(delta)
            .expect("network account delta should apply since it was accepted by the mempool");

        self.inflight.push_back(state);
    }

    /// Commits the oldest account state delta.
    ///
    /// # Panics
    ///
    /// Panics if there are no deltas to commit.
    pub fn commit_delta(&mut self) {
        self.committed = self.inflight.pop_front().expect("must have a delta to commit").into();
    }

    /// Reverts the newest account state delta.
    ///
    /// Returns `true` if this reverted the account creation delta. The caller _must_ handle
    /// cleanup as calls to `latest_account` will panic afterwards.
    ///
    /// # Panics
    ///
    /// Panics if there are no deltas to revert.
    #[must_use = "must handle account removal if this returns true"]
    pub fn revert_delta(&mut self) -> bool {
        self.inflight.pop_back().expect("must have a delta to revert");
        self.committed.is_none() && self.inflight.is_empty()
    }

    /// Returns the latest inflight account state.
    pub fn latest_account(&self) -> Account {
        self.inflight
            .back()
            .or(self.committed.as_ref())
            .expect("account must have either a committed or inflight state")
            .clone()
    }

    /// Returns `true` if there are no inflight deltas.
    pub fn has_no_inflight(&self) -> bool {
        self.inflight.is_empty()
    }
}

// NOTE POOL
// ================================================================================================

/// Manages available and nullified notes for a network account.
#[derive(Clone, Default)]
pub struct NotePool {
    /// Unconsumed notes available for consumption.
    available: HashMap<Nullifier, InflightNetworkNote>,

    /// Notes consumed by inflight transactions (not yet committed).
    nullified: HashMap<Nullifier, InflightNetworkNote>,
}

impl NotePool {
    /// Returns an iterator over notes that are available and not in backoff.
    pub fn available_notes(
        &self,
        block_num: &BlockNumber,
    ) -> impl Iterator<Item = &InflightNetworkNote> {
        self.available.values().filter(|&note| note.is_available(*block_num))
    }

    /// Adds a new network note making it available for consumption.
    pub fn add_note(&mut self, note: SingleTargetNetworkNote) {
        self.available.insert(note.nullifier(), InflightNetworkNote::new(note));
    }

    /// Removes the note completely (used when reverting note creation).
    pub fn remove_note(&mut self, nullifier: Nullifier) {
        self.available.remove(&nullifier);
        self.nullified.remove(&nullifier);
    }

    /// Marks a note as being consumed by moving it to the nullified set.
    ///
    /// Returns `Err(())` if the note does not exist or was already nullified.
    pub fn nullify(&mut self, nullifier: Nullifier) -> Result<(), ()> {
        if let Some(note) = self.available.remove(&nullifier) {
            self.nullified.insert(nullifier, note);
            Ok(())
        } else {
            tracing::warn!(%nullifier, "note must be available to nullify");
            Err(())
        }
    }

    /// Commits a nullifier, removing the associated note entirely.
    ///
    /// Silently ignores if the nullifier is not present.
    pub fn commit_nullifier(&mut self, nullifier: Nullifier) {
        let _ = self.nullified.remove(&nullifier);
    }

    /// Reverts a nullifier, making the note available again.
    pub fn revert_nullifier(&mut self, nullifier: Nullifier) {
        // Transactions can be reverted out of order.
        if let Some(note) = self.nullified.remove(&nullifier) {
            self.available.insert(nullifier, note);
        }
    }

    /// Drops all notes that have exceeded the maximum attempt count.
    pub fn drop_failing_notes(&mut self, max_attempts: usize) {
        self.available.retain(|_, note| note.attempt_count() < max_attempts);
    }

    /// Marks the specified notes as failed.
    pub fn fail_notes(&mut self, nullifiers: &[Nullifier], block_num: BlockNumber) {
        for nullifier in nullifiers {
            if let Some(note) = self.available.get_mut(nullifier) {
                note.fail(block_num);
            } else {
                tracing::warn!(%nullifier, "failed note is not in account's state");
            }
        }
    }

    /// Returns `true` if there are no notes being tracked.
    pub fn is_empty(&self) -> bool {
        self.available.is_empty() && self.nullified.is_empty()
    }
}

// NETWORK ACCOUNT EFFECT
// ================================================================================================

/// Represents the effect of a transaction on a network account.
#[derive(Clone)]
pub enum NetworkAccountEffect {
    Created(Account),
    Updated(AccountDelta),
}

impl NetworkAccountEffect {
    pub fn from_protocol(update: &AccountUpdateDetails) -> Option<Self> {
        let update = match update {
            AccountUpdateDetails::Private => return None,
            AccountUpdateDetails::Delta(update) if update.is_full_state() => {
                NetworkAccountEffect::Created(
                    Account::try_from(update)
                        .expect("Account should be derivable by full state AccountDelta"),
                )
            },
            AccountUpdateDetails::Delta(update) => NetworkAccountEffect::Updated(update.clone()),
        };

        update.protocol_account_id().is_network().then_some(update)
    }

    pub fn network_account_id(&self) -> NetworkAccountId {
        // SAFETY: This is a network account by construction.
        self.protocol_account_id().try_into().unwrap()
    }

    fn protocol_account_id(&self) -> AccountId {
        match self {
            NetworkAccountEffect::Created(acc) => acc.id(),
            NetworkAccountEffect::Updated(delta) => delta.id(),
        }
    }
}

#[cfg(test)]
mod tests {
    use miden_protocol::block::BlockNumber;

    #[rstest::rstest]
    #[test]
    #[case::all_zero(Some(BlockNumber::GENESIS), BlockNumber::GENESIS, 0, true)]
    #[case::no_attempts(None, BlockNumber::GENESIS, 0, true)]
    #[case::one_attempt(Some(BlockNumber::GENESIS), BlockNumber::from(2), 1, true)]
    #[case::three_attempts(Some(BlockNumber::GENESIS), BlockNumber::from(3), 3, true)]
    #[case::ten_attempts(Some(BlockNumber::GENESIS), BlockNumber::from(13), 10, true)]
    #[case::twenty_attempts(Some(BlockNumber::GENESIS), BlockNumber::from(149), 20, true)]
    #[case::one_attempt_false(Some(BlockNumber::GENESIS), BlockNumber::from(1), 1, false)]
    #[case::three_attempts_false(Some(BlockNumber::GENESIS), BlockNumber::from(2), 3, false)]
    #[case::ten_attempts_false(Some(BlockNumber::GENESIS), BlockNumber::from(12), 10, false)]
    #[case::twenty_attempts_false(Some(BlockNumber::GENESIS), BlockNumber::from(148), 20, false)]
    fn backoff_has_passed(
        #[case] last_attempt_block_num: Option<BlockNumber>,
        #[case] current_block_num: BlockNumber,
        #[case] attempt_count: usize,
        #[case] backoff_should_have_passed: bool,
    ) {
        use crate::actor::has_backoff_passed;

        assert_eq!(
            backoff_should_have_passed,
            has_backoff_passed(current_block_num, last_attempt_block_num, attempt_count)
        );
    }
}
