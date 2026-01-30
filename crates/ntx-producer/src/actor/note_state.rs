use std::collections::{HashMap, VecDeque};

use miden_node_proto::domain::account::NetworkAccountId;
use miden_node_proto::domain::note::SingleTargetNetworkNote;
use miden_protocol::account::delta::AccountUpdateDetails;
use miden_protocol::account::{Account, AccountDelta, AccountId};
use miden_protocol::block::BlockNumber;
use miden_protocol::note::Nullifier;

use crate::actor::inflight_note::InflightNetworkNote;

// ACCOUNT STATE
// ================================================================================================

/// Tracks the state of a network account and its notes.
#[derive(Clone)]
pub struct NetworkAccountNoteState {
    /// The committed account state, if any.
    ///
    /// Its possible this is `None` if the account creation transaction is still inflight.
    committed: Option<Account>,

    /// Inflight account updates in chronological order.
    inflight: VecDeque<Account>,

    /// Unconsumed notes of this account.
    available_notes: HashMap<Nullifier, InflightNetworkNote>,

    /// Notes which have been consumed by transactions that are still inflight.
    nullified_notes: HashMap<Nullifier, InflightNetworkNote>,
}

impl NetworkAccountNoteState {
    /// Creates a new account state from the supplied account and notes.
    pub fn new(account: Account, notes: Vec<SingleTargetNetworkNote>) -> Self {
        let account_id = NetworkAccountId::try_from(account.id())
            .expect("only network accounts are used for account state");

        let mut state = Self {
            committed: Some(account),
            inflight: VecDeque::default(),
            available_notes: HashMap::default(),
            nullified_notes: HashMap::default(),
        };

        for note in notes {
            // Currently only support single target network notes in NTB.
            assert!(
                note.account_id() == account_id,
                "Notes supplied into account state must match expected account ID"
            );
            state.add_note(note);
        }

        state
    }

    /// Returns an iterator over inflight notes that are not currently within their respective
    /// backoff periods based on block number.
    pub fn available_notes(
        &self,
        block_num: &BlockNumber,
    ) -> impl Iterator<Item = &InflightNetworkNote> {
        self.available_notes.values().filter(|&note| note.is_available(*block_num))
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
    /// # Returns
    ///
    /// Returns `true` if this reverted the account creation delta. The caller _must_ remove this
    /// account and associated notes as calls to `account` will panic.
    ///
    /// # Panics
    ///
    /// Panics if there are no deltas to revert.
    #[must_use = "must remove this account and its notes"]
    pub fn revert_delta(&mut self) -> bool {
        self.inflight.pop_back().expect("must have a delta to revert");
        self.committed.is_none() && self.inflight.is_empty()
    }

    /// Adds a new network note making it available for consumption.
    pub fn add_note(&mut self, note: SingleTargetNetworkNote) {
        self.available_notes.insert(note.nullifier(), InflightNetworkNote::new(note));
    }

    /// Removes the note completely.
    pub fn revert_note(&mut self, note: Nullifier) {
        // Transactions can be reverted out of order.
        //
        // This means the tx which nullified the note might not have been reverted yet, and the note
        // might still be in the nullified
        self.available_notes.remove(&note);
        self.nullified_notes.remove(&note);
    }

    /// Marks a note as being consumed.
    ///
    /// The note data is retained until the nullifier is committed.
    ///
    /// Returns `Err(())` if the note does not exist or was already nullified.
    pub fn add_nullifier(&mut self, nullifier: Nullifier) -> Result<(), ()> {
        if let Some(note) = self.available_notes.remove(&nullifier) {
            self.nullified_notes.insert(nullifier, note);
            Ok(())
        } else {
            tracing::warn!(%nullifier, "note must be available to nullify");
            Err(())
        }
    }

    /// Marks a nullifier as being committed, removing the associated note data entirely.
    ///
    /// Silently ignores the request if the nullifier is not present, which can happen
    /// if the note's transaction wasn't available when the nullifier was added.
    pub fn commit_nullifier(&mut self, nullifier: Nullifier) {
        // we might not have this if we didn't add it with `add_nullifier`
        // in case it's transaction wasn't available in the first place.
        // It shouldn't happen practically, since we skip them if the
        // relevant account cannot be retrieved via `fetch`.

        let _ = self.nullified_notes.remove(&nullifier);
    }

    /// Reverts a nullifier, marking the associated note as available again.
    pub fn revert_nullifier(&mut self, nullifier: Nullifier) {
        // Transactions can be reverted out of order.
        //
        // The note may already have been fully removed by `revert_note` if the transaction creating
        // the note was reverted before the transaction that consumed it.
        if let Some(note) = self.nullified_notes.remove(&nullifier) {
            self.available_notes.insert(nullifier, note);
        }
    }

    /// Drops all notes that have failed to be consumed after a certain number of attempts.
    pub fn drop_failing_notes(&mut self, max_attempts: usize) {
        self.available_notes.retain(|_, note| note.attempt_count() < max_attempts);
    }

    /// Returns the latest inflight account state.
    pub fn latest_account(&self) -> Account {
        self.inflight
            .back()
            .or(self.committed.as_ref())
            .expect("account must have either a committed or inflight state")
            .clone()
    }

    /// Returns `true` if there is no inflight state being tracked.
    ///
    /// This implies this state is safe to remove without losing uncommitted data.
    pub fn is_empty(&self) -> bool {
        self.inflight.is_empty()
            && self.available_notes.is_empty()
            && self.nullified_notes.is_empty()
    }

    /// Marks the specified notes as failed.
    pub fn fail_notes(&mut self, nullifiers: &[Nullifier], block_num: BlockNumber) {
        for nullifier in nullifiers {
            if let Some(note) = self.available_notes.get_mut(nullifier) {
                note.fail(block_num);
            } else {
                tracing::warn!(%nullifier, "failed note is not in account's state");
            }
        }
    }
}

// NETWORK ACCOUNT UPDATE
// ================================================================================================

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
