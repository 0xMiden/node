use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::num::NonZeroUsize;

use miden_node_proto::domain::account::NetworkAccountId;
use miden_node_proto::domain::mempool::MempoolEvent;
use miden_node_proto::domain::note::{NetworkNote, SingleTargetNetworkNote};
use miden_node_utils::tracing::OpenTelemetrySpanExt;
use miden_protocol::account::Account;
use miden_protocol::account::delta::AccountUpdateDetails;
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::note::{Note, Nullifier};
use miden_protocol::transaction::{PartialBlockchain, TransactionId};
use tracing::instrument;

use super::ActorShutdownReason;
use super::note_state::{NetworkAccountEffect, NetworkAccountNoteState};
use crate::COMPONENT;
use crate::actor::inflight_note::InflightNetworkNote;
use crate::builder::ChainState;
use crate::store::{StoreClient, StoreError};

// TRANSACTION CANDIDATE
// ================================================================================================

/// A candidate network transaction.
///
/// Contains the data pertaining to a specific network account which can be used to build a network
/// transaction.
#[derive(Clone, Debug)]
pub struct TransactionCandidate {
    /// The current inflight state of the account.
    pub account: Account,

    /// A set of notes addressed to this network account.
    pub notes: Vec<InflightNetworkNote>,

    /// The latest locally committed block header.
    ///
    /// This should be used as the reference block during transaction execution.
    pub chain_tip_header: BlockHeader,

    /// The chain MMR, which lags behind the tip by one block.
    pub chain_mmr: PartialBlockchain,
}

// NETWORK ACCOUNT STATE
// ================================================================================================

/// The current state of a network account.
#[derive(Clone)]
pub struct NetworkAccountState {
    /// The network account ID corresponding to the network account this state represents.
    account_id: NetworkAccountId,

    /// Component of this state which Contains the committed and inflight account updates as well
    /// as available and nullified notes.
    account: NetworkAccountNoteState,

    /// Uncommitted transactions which have some impact on the network state.
    ///
    /// This is tracked so we can commit or revert such transaction effects. Transactions _without_
    /// an impact are ignored.
    inflight_txs: BTreeMap<TransactionId, TransactionImpact>,

    /// Nullifiers of all network notes targeted at this account.
    ///
    /// Used to filter mempool events: when a `TransactionAdded` event reports consumed nullifiers,
    /// only those present in this set are processed (moved from `available_notes` to
    /// `nullified_notes`). Nullifiers are added when notes are loaded or created, and removed
    /// when the consuming transaction is committed.
    known_nullifiers: HashSet<Nullifier>,
}

impl NetworkAccountState {
    /// Load's all available network notes from the store, along with the required account states.
    #[instrument(target = COMPONENT, name = "ntx.state.load", skip_all)]
    pub async fn load(
        account: Account,
        account_id: NetworkAccountId,
        store: &StoreClient,
        block_num: BlockNumber,
    ) -> Result<Self, StoreError> {
        let notes = store.get_unconsumed_network_notes(account_id, block_num.as_u32()).await?;
        let notes = notes
            .into_iter()
            .map(|note| {
                let NetworkNote::SingleTarget(note) = note;
                note
            })
            .collect::<Vec<_>>();

        let known_nullifiers: HashSet<Nullifier> =
            notes.iter().map(SingleTargetNetworkNote::nullifier).collect();

        let account = NetworkAccountNoteState::new(account, notes);

        let state = Self {
            account,
            account_id,
            inflight_txs: BTreeMap::default(),
            known_nullifiers,
        };

        state.inject_telemetry();

        Ok(state)
    }

    /// Selects the next candidate network transaction.
    ///
    /// # Parameters
    ///
    /// - `limit`: Maximum number of notes to include in the transaction.
    /// - `max_note_attempts`: Maximum number of execution attempts before a note is dropped.
    /// - `chain_state`: Current chain state for the transaction.
    #[instrument(target = COMPONENT, name = "ntx.state.select_candidate", skip_all)]
    pub fn select_candidate(
        &mut self,
        limit: NonZeroUsize,
        max_note_attempts: usize,
        chain_state: ChainState,
    ) -> Option<TransactionCandidate> {
        // Remove notes that have failed too many times.
        self.account.drop_failing_notes(max_note_attempts);

        // Skip empty accounts, and prune them.
        // This is how we keep the number of accounts bounded.
        if self.account.is_empty() {
            return None;
        }

        // Select notes from the account that can be consumed or are ready for a retry.
        let notes = self
            .account
            .available_notes(&chain_state.chain_tip_header.block_num())
            .take(limit.get())
            .cloned()
            .collect::<Vec<_>>();

        // Skip accounts with no available notes.
        if notes.is_empty() {
            return None;
        }

        let (chain_tip_header, chain_mmr) = chain_state.into_parts();
        TransactionCandidate {
            account: self.account.latest_account(),
            notes,
            chain_tip_header,
            chain_mmr,
        }
        .into()
    }

    /// Marks notes of a previously selected candidate as failed.
    ///
    /// Does not remove the candidate from the in-progress pool.
    #[instrument(target = COMPONENT, name = "ntx.state.notes_failed", skip_all)]
    pub fn notes_failed(&mut self, notes: &[Note], block_num: BlockNumber) {
        let nullifiers = notes.iter().map(Note::nullifier).collect::<Vec<_>>();
        self.account.fail_notes(nullifiers.as_slice(), block_num);
    }

    /// Updates state with the mempool event.
    #[instrument(target = COMPONENT, name = "ntx.state.mempool_update", skip_all)]
    pub fn mempool_update(&mut self, update: &MempoolEvent) -> Option<ActorShutdownReason> {
        let span = tracing::Span::current();
        span.set_attribute("mempool_event.kind", update.kind());

        match update {
            MempoolEvent::TransactionAdded {
                id,
                nullifiers,
                network_notes,
                account_delta,
            } => {
                // Filter network notes relevant to this account.
                let network_notes = filter_by_account_id_and_map_to_single_target(
                    self.account_id,
                    network_notes.clone(),
                );
                self.add_transaction(*id, nullifiers, &network_notes, account_delta.as_ref());
            },
            MempoolEvent::TransactionsReverted(txs) => {
                for tx in txs {
                    let shutdown_reason = self.revert_transaction(*tx);
                    if shutdown_reason.is_some() {
                        return shutdown_reason;
                    }
                }
            },
            MempoolEvent::BlockCommitted { txs, .. } => {
                for tx in txs {
                    self.commit_transaction(*tx);
                }
            },
        }
        self.inject_telemetry();

        // No shutdown, continue running actor.
        None
    }

    /// Handles a [`MempoolEvent::TransactionAdded`] event.
    fn add_transaction(
        &mut self,
        id: TransactionId,
        nullifiers: &[Nullifier],
        network_notes: &[SingleTargetNetworkNote],
        account_delta: Option<&AccountUpdateDetails>,
    ) {
        // Skip transactions we already know about.
        //
        // This can occur since both ntx builder and the mempool might inform us of the same
        // transaction. Once when it was submitted to the mempool, and once by the mempool event.
        if self.inflight_txs.contains_key(&id) {
            return;
        }

        let mut tx_impact = TransactionImpact::default();
        if let Some(update) = account_delta.and_then(NetworkAccountEffect::from_protocol) {
            let account_id = update.network_account_id();
            if account_id == self.account_id {
                match update {
                    NetworkAccountEffect::Updated(account_delta) => {
                        self.account.add_delta(&account_delta);
                        tx_impact.account_delta = Some(account_id);
                    },
                    NetworkAccountEffect::Created(_) => {},
                }
            }
        }
        for note in network_notes {
            assert_eq!(
                note.account_id(),
                self.account_id,
                "note's account ID does not match network account actor's account ID"
            );
            tx_impact.notes.insert(note.nullifier());
            self.known_nullifiers.insert(note.nullifier());
            self.account.add_note(note.clone());
        }
        for nullifier in nullifiers {
            // Ignore nullifiers that aren't network note nullifiers.
            if !self.known_nullifiers.contains(nullifier) {
                continue;
            }
            tx_impact.nullifiers.insert(*nullifier);
            // We don't use the entry wrapper here because the account must already exist.
            let _ = self.account.add_nullifier(*nullifier);
        }

        if !tx_impact.is_empty() {
            self.inflight_txs.insert(id, tx_impact);
        }
    }

    /// Handles [`MempoolEvent::BlockCommitted`] events.
    fn commit_transaction(&mut self, tx: TransactionId) {
        // We only track transactions which have an impact on the network state.
        let Some(impact) = self.inflight_txs.remove(&tx) else {
            return;
        };

        if let Some(delta_account_id) = impact.account_delta {
            if delta_account_id == self.account_id {
                self.account.commit_delta();
            }
        }

        for nullifier in impact.nullifiers {
            if self.known_nullifiers.remove(&nullifier) {
                // Its possible for the account to no longer exist if the transaction creating it
                // was reverted.
                self.account.commit_nullifier(nullifier);
            }
        }
    }

    /// Handles [`MempoolEvent::TransactionsReverted`] events.
    fn revert_transaction(&mut self, tx: TransactionId) -> Option<ActorShutdownReason> {
        // We only track transactions which have an impact on the network state.
        let Some(impact) = self.inflight_txs.remove(&tx) else {
            tracing::debug!("transaction {tx} not found in inflight transactions");
            return None;
        };

        // Revert account creation.
        if let Some(account_id) = impact.account_delta {
            // Account creation reverted, actor must stop.
            if account_id == self.account_id && self.account.revert_delta() {
                return Some(ActorShutdownReason::AccountReverted(account_id));
            }
        }

        // Revert notes.
        for note_nullifier in impact.notes {
            if self.known_nullifiers.contains(&note_nullifier) {
                self.account.revert_note(note_nullifier);
                self.known_nullifiers.remove(&note_nullifier);
            }
        }

        // Revert nullifiers.
        for nullifier in impact.nullifiers {
            if self.known_nullifiers.contains(&nullifier) {
                self.account.revert_nullifier(nullifier);
                self.known_nullifiers.remove(&nullifier);
            }
        }

        None
    }

    /// Adds stats to the current tracing span.
    ///
    /// Note that these are only visible in the OpenTelemetry context, as conventional tracing
    /// does not track fields added dynamically.
    fn inject_telemetry(&self) {
        let span = tracing::Span::current();

        span.set_attribute("ntx.state.transactions", self.inflight_txs.len());
        span.set_attribute("ntx.state.notes.total", self.known_nullifiers.len());
    }
}

/// The impact a transaction has on the state.
#[derive(Clone, Default)]
struct TransactionImpact {
    /// The network account this transaction added an account delta to.
    account_delta: Option<NetworkAccountId>,

    /// Network notes this transaction created.
    notes: BTreeSet<Nullifier>,

    /// Network notes this transaction consumed.
    nullifiers: BTreeSet<Nullifier>,
}

impl TransactionImpact {
    fn is_empty(&self) -> bool {
        self.account_delta.is_none() && self.notes.is_empty() && self.nullifiers.is_empty()
    }
}

/// Filters network notes by account ID and maps them to single target network notes.
fn filter_by_account_id_and_map_to_single_target(
    account_id: NetworkAccountId,
    notes: Vec<NetworkNote>,
) -> Vec<SingleTargetNetworkNote> {
    notes
        .into_iter()
        .filter_map(|note| match note {
            NetworkNote::SingleTarget(note) if note.account_id() == account_id => Some(note),
            NetworkNote::SingleTarget(_) => None,
        })
        .collect::<Vec<_>>()
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};

    use miden_protocol::account::{AccountBuilder, AccountStorageMode, AccountType};
    use miden_protocol::asset::{Asset, FungibleAsset};
    use miden_protocol::crypto::rand::RpoRandomCoin;
    use miden_protocol::note::{Note, NoteAttachment, NoteExecutionHint, NoteType};
    use miden_protocol::testing::account_id::AccountIdBuilder;
    use miden_protocol::transaction::TransactionId;
    use miden_protocol::{EMPTY_WORD, Felt, Hasher};
    use miden_standards::note::{NetworkAccountTarget, create_p2id_note};

    use super::*;

    // HELPERS
    // ============================================================================================

    /// Creates a network account for testing.
    fn create_network_account(seed: u8) -> Account {
        use miden_protocol::testing::noop_auth_component::NoopAuthComponent;
        use miden_standards::account::wallets::BasicWallet;

        AccountBuilder::new([seed; 32])
            .account_type(AccountType::RegularAccountUpdatableCode)
            .storage_mode(AccountStorageMode::Network)
            .with_component(BasicWallet)
            .with_auth_component(NoopAuthComponent)
            .build_existing()
            .expect("should be able to build test account")
    }

    /// Creates a faucet account ID for testing.
    fn create_faucet_id(seed: u8) -> miden_protocol::account::AccountId {
        AccountIdBuilder::new()
            .account_type(AccountType::FungibleFaucet)
            .storage_mode(AccountStorageMode::Public)
            .build_with_seed([seed; 32])
    }

    /// Creates a note targeted at the given network account.
    fn create_network_note(
        target_account_id: miden_protocol::account::AccountId,
        seed: u8,
    ) -> Note {
        let coin_seed: [u64; 4] =
            [u64::from(seed), u64::from(seed) + 1, u64::from(seed) + 2, u64::from(seed) + 3];
        let rng = Arc::new(Mutex::new(RpoRandomCoin::new(coin_seed.map(Felt::new).into())));
        let mut rng = rng.lock().unwrap();

        let faucet_id = create_faucet_id(seed.wrapping_add(100));

        let target = NetworkAccountTarget::new(target_account_id, NoteExecutionHint::Always)
            .expect("NetworkAccountTarget creation should succeed for network account");
        let attachment: NoteAttachment = target.into();

        create_p2id_note(
            target_account_id,
            target_account_id,
            vec![Asset::Fungible(FungibleAsset::new(faucet_id, 10).unwrap())],
            NoteType::Public,
            attachment,
            &mut *rng,
        )
        .expect("note creation should succeed")
    }

    /// Creates a `SingleTargetNetworkNote` from a `Note`.
    fn to_single_target_note(note: Note) -> SingleTargetNetworkNote {
        SingleTargetNetworkNote::try_from(note).expect("should convert to SingleTargetNetworkNote")
    }

    /// Creates a mock `TransactionId` for testing.
    fn mock_tx_id(seed: u8) -> TransactionId {
        TransactionId::new(
            Hasher::hash(&[seed; 32]),
            Hasher::hash(&[seed.wrapping_add(1); 32]),
            EMPTY_WORD,
            EMPTY_WORD,
        )
    }

    /// Creates a mock `BlockHeader` for testing.
    fn mock_block_header(block_num: u32) -> miden_protocol::block::BlockHeader {
        use miden_node_utils::fee::test_fee_params;
        use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SecretKey;

        miden_protocol::block::BlockHeader::new(
            0,
            EMPTY_WORD,
            BlockNumber::from(block_num),
            EMPTY_WORD,
            EMPTY_WORD,
            EMPTY_WORD,
            EMPTY_WORD,
            EMPTY_WORD,
            EMPTY_WORD,
            SecretKey::new().public_key(),
            test_fee_params(),
            0,
        )
    }

    impl NetworkAccountState {
        /// Creates a new `NetworkAccountState` for testing.
        ///
        /// This mirrors the behavior of `load()` but with provided notes instead of
        /// fetching from the store.
        #[cfg(test)]
        pub fn new_for_testing(
            account: Account,
            account_id: NetworkAccountId,
            notes: Vec<SingleTargetNetworkNote>,
        ) -> Self {
            let known_nullifiers: HashSet<Nullifier> =
                notes.iter().map(SingleTargetNetworkNote::nullifier).collect();

            let account = NetworkAccountNoteState::new(account, notes);

            Self {
                account,
                account_id,
                inflight_txs: BTreeMap::default(),
                known_nullifiers,
            }
        }
    }

    // TESTS
    // ============================================================================================

    /// Tests that initial notes loaded into `NetworkAccountState` have their nullifiers
    /// registered in `known_nullifiers`.
    #[test]
    fn test_initial_notes_have_nullifiers_indexed() {
        let account = create_network_account(1);
        let account_id = account.id();
        let network_account_id =
            NetworkAccountId::try_from(account_id).expect("should be a network account");

        let note1 = to_single_target_note(create_network_note(account_id, 1));
        let note2 = to_single_target_note(create_network_note(account_id, 2));
        let nullifier1 = note1.nullifier();
        let nullifier2 = note2.nullifier();

        let state =
            NetworkAccountState::new_for_testing(account, network_account_id, vec![note1, note2]);

        assert!(
            state.known_nullifiers.contains(&nullifier1),
            "known_nullifiers should contain first note's nullifier"
        );
        assert!(
            state.known_nullifiers.contains(&nullifier2),
            "known_nullifiers should contain second note's nullifier"
        );
        assert_eq!(
            state.known_nullifiers.len(),
            2,
            "known_nullifiers should have exactly 2 entries"
        );
    }

    /// Tests that when a `TransactionAdded` event arrives with nullifiers from initial notes,
    /// those notes are properly moved from `available_notes` to `nullified_notes`.
    #[test]
    fn test_mempool_event_nullifies_initial_notes() {
        let account = create_network_account(1);
        let account_id = account.id();
        let network_account_id =
            NetworkAccountId::try_from(account_id).expect("should be a network account");

        let note1 = to_single_target_note(create_network_note(account_id, 1));
        let note2 = to_single_target_note(create_network_note(account_id, 2));
        let nullifier1 = note1.nullifier();
        let nullifier2 = note2.nullifier();

        let mut state =
            NetworkAccountState::new_for_testing(account, network_account_id, vec![note1, note2]);

        let available_count = state.account.available_notes(&BlockNumber::from(0)).count();
        assert_eq!(available_count, 2, "both notes should be available initially");

        let tx_id = mock_tx_id(1);
        let event = MempoolEvent::TransactionAdded {
            id: tx_id,
            nullifiers: vec![nullifier1],
            network_notes: vec![],
            account_delta: None,
        };

        let shutdown = state.mempool_update(&event);
        assert!(shutdown.is_none(), "mempool_update should not trigger shutdown");

        let available_nullifiers: Vec<_> = state
            .account
            .available_notes(&BlockNumber::from(0))
            .map(|n| n.to_inner().nullifier())
            .collect();
        assert!(
            !available_nullifiers.contains(&nullifier1),
            "note1 should no longer be available"
        );
        assert!(available_nullifiers.contains(&nullifier2), "note2 should still be available");
        assert_eq!(available_nullifiers.len(), 1, "only one note should be available");

        assert!(
            state.inflight_txs.contains_key(&tx_id),
            "transaction should be tracked in inflight_txs"
        );
    }

    /// Tests that after committing a transaction, the nullifier is removed from `known_nullifiers`.
    #[test]
    fn test_commit_removes_nullifier_from_index() {
        let account = create_network_account(1);
        let account_id = account.id();
        let network_account_id =
            NetworkAccountId::try_from(account_id).expect("should be a network account");

        let note1 = to_single_target_note(create_network_note(account_id, 1));
        let nullifier1 = note1.nullifier();

        let mut state =
            NetworkAccountState::new_for_testing(account, network_account_id, vec![note1]);

        let tx_id = mock_tx_id(1);
        let event = MempoolEvent::TransactionAdded {
            id: tx_id,
            nullifiers: vec![nullifier1],
            network_notes: vec![],
            account_delta: None,
        };
        state.mempool_update(&event);

        assert!(
            state.known_nullifiers.contains(&nullifier1),
            "nullifier should still be in index while transaction is inflight"
        );

        let commit_event = MempoolEvent::BlockCommitted {
            header: Box::new(mock_block_header(1)),
            txs: vec![tx_id],
        };
        state.mempool_update(&commit_event);

        assert!(
            !state.known_nullifiers.contains(&nullifier1),
            "nullifier should be removed from index after commit"
        );
    }

    /// Tests that reverting a transaction restores the note to `available_notes`.
    #[test]
    fn test_revert_restores_note_to_available() {
        let account = create_network_account(1);
        let account_id = account.id();
        let network_account_id =
            NetworkAccountId::try_from(account_id).expect("should be a network account");

        let note1 = to_single_target_note(create_network_note(account_id, 1));
        let nullifier1 = note1.nullifier();

        let mut state =
            NetworkAccountState::new_for_testing(account, network_account_id, vec![note1]);

        let tx_id = mock_tx_id(1);
        let event = MempoolEvent::TransactionAdded {
            id: tx_id,
            nullifiers: vec![nullifier1],
            network_notes: vec![],
            account_delta: None,
        };
        state.mempool_update(&event);

        // Verify note is not available
        let available_count = state.account.available_notes(&BlockNumber::from(0)).count();
        assert_eq!(available_count, 0, "note should not be available after being consumed");

        // Revert the transaction
        let revert_event =
            MempoolEvent::TransactionsReverted(HashSet::from_iter(std::iter::once(tx_id)));
        state.mempool_update(&revert_event);

        // Verify note is available again
        let available_nullifiers: Vec<_> = state
            .account
            .available_notes(&BlockNumber::from(0))
            .map(|n| n.to_inner().nullifier())
            .collect();
        assert!(
            available_nullifiers.contains(&nullifier1),
            "note should be available again after revert"
        );
    }

    /// Tests that nullifiers from dynamically added notes are also indexed.
    #[test]
    fn test_dynamically_added_notes_are_indexed() {
        let account = create_network_account(1);
        let account_id = account.id();
        let network_account_id =
            NetworkAccountId::try_from(account_id).expect("should be a network account");

        let mut state = NetworkAccountState::new_for_testing(account, network_account_id, vec![]);

        assert!(state.known_nullifiers.is_empty(), "known_nullifiers should be empty initially");

        let new_note = to_single_target_note(create_network_note(account_id, 1));
        let new_nullifier = new_note.nullifier();

        let tx_id = mock_tx_id(1);
        let event = MempoolEvent::TransactionAdded {
            id: tx_id,
            nullifiers: vec![],
            network_notes: vec![NetworkNote::SingleTarget(new_note)],
            account_delta: None,
        };

        state.mempool_update(&event);

        // Verify the new note's nullifier is now indexed
        assert!(
            state.known_nullifiers.contains(&new_nullifier),
            "dynamically added note's nullifier should be indexed"
        );

        // Verify the note is available
        let available_nullifiers: Vec<_> = state
            .account
            .available_notes(&BlockNumber::from(0))
            .map(|n| n.to_inner().nullifier())
            .collect();
        assert!(
            available_nullifiers.contains(&new_nullifier),
            "dynamically added note should be available"
        );
    }
}
