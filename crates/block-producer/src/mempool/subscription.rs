use std::collections::{BTreeMap, HashSet};
use std::ops::Mul;

use miden_node_proto::domain::mempool::MempoolEvent;
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::transaction::{OutputNote, TransactionId};
use miden_standards::note::NetworkNoteExt;
use tokio::sync::mpsc;

use crate::domain::transaction::AuthenticatedTransaction;

/// Coordinates mempool event delivery for a single subscriber.
///
/// Retains the active subscriber channel (if any) and an in-memory queue of uncommitted
/// transaction events so new subscriptions can immediately replay pending updates.
#[derive(Clone, Debug)]
pub(crate) struct SubscriptionProvider {
    /// The latest event subscription, if any.
    ///
    /// The only current interested party is the network transaction builder, so one subscription
    /// is enough.
    subscription: Option<mpsc::Sender<MempoolEvent>>,

    /// The latest committed block number.
    ///
    /// This is used to ensure synchronicity with new subscribers.
    chain_tip: BlockNumber,

    /// Tracks all uncommitted transaction events. These events must be resent on start
    /// of a new subscription since the subscriber will only have data up to the latest
    /// committed block and would otherwise miss these uncommitted transactions.
    ///
    /// The size is bounded by removing events as they are committed or reverted, and as
    /// such this is always bound to the current amount of inflight transactions.
    inflight_txs: InflightTransactions,
}

impl PartialEq for SubscriptionProvider {
    fn eq(&self, other: &Self) -> bool {
        self.chain_tip == other.chain_tip && self.inflight_txs == other.inflight_txs
    }
}

impl SubscriptionProvider {
    pub fn new(chain_tip: BlockNumber) -> Self {
        Self {
            chain_tip,
            subscription: None,
            inflight_txs: InflightTransactions::default(),
        }
    }

    /// Creates a new [`MempoolEvent`] subscription.
    ///
    /// This replaces any existing subscription.
    /// Any previous subscriber is dropped and must resubscribe to continue receiving events.
    pub fn subscribe(&mut self) -> mpsc::Receiver<MempoolEvent> {
        // We should leave enough space to at least send the uncommitted events (plus some extra).
        let capacity = self.inflight_txs.len().mul(2).max(1024);
        let (tx, rx) = mpsc::channel(capacity);
        self.subscription.replace(tx);

        // Send each uncommitted tx event in chronological order.
        //
        // The ordering is guaranteed by the tracker.
        //
        // We don't clear the queue so that they're available for other new subscriptions.
        // The queue size is managed by instead removing events once they're committed or reverted.
        for tx in self.inflight_txs.iter() {
            Self::send_event(&mut self.subscription, tx.clone());
        }

        rx
    }

    /// Records a newly added transaction in the inflight queue and forwards the event to the
    /// subscriber.
    pub(super) fn transaction_added(&mut self, tx: &AuthenticatedTransaction) {
        let id = tx.id();
        let nullifiers = tx.nullifiers().collect();
        let network_notes = tx
            .output_notes()
            .filter_map(|note| match note {
                OutputNote::Full(inner) => inner.clone().into_account_target_network_note().ok(),
                _ => None,
            })
            .collect();
        let account_delta =
            tx.account_id().is_network().then(|| tx.account_update().details().clone());
        let event = MempoolEvent::TransactionAdded {
            id,
            nullifiers,
            network_notes,
            account_delta,
        };

        self.inflight_txs.insert(event.clone());
        Self::send_event(&mut self.subscription, event);
    }

    /// Records a committed block, prunes replayed transactions, and forwards the event so future
    /// subscribers continue from the latest chain tip.
    pub(super) fn block_committed(&mut self, header: BlockHeader, txs: Vec<TransactionId>) {
        self.chain_tip = header.block_num();
        for tx in &txs {
            self.inflight_txs.remove(tx);
        }

        Self::send_event(
            &mut self.subscription,
            MempoolEvent::BlockCommitted { header: Box::new(header), txs },
        );
    }

    /// Removes reverted transactions from the inflight queue and notifies the subscriber so they
    /// can drop or retry the affected items.
    pub(super) fn txs_reverted(&mut self, txs: HashSet<TransactionId>) {
        for tx in &txs {
            self.inflight_txs.remove(tx);
        }
        Self::send_event(&mut self.subscription, MempoolEvent::TransactionsReverted(txs));
    }

    /// Sends a [`MempoolEvent`] to the subscriber, if any.
    ///
    /// If the send fails, the subscription is cancelled and the event is dropped, so callers must
    /// resubscribe to continue receiving updates.
    ///
    /// This function does not take `&self` to work-around borrowing issues
    /// where both the sender and inflight events need to be borrowed at the same time.
    fn send_event(subscription: &mut Option<mpsc::Sender<MempoolEvent>>, event: MempoolEvent) {
        let Some(sender) = subscription else {
            return;
        };

        // If sending fails, end the subscription to prevent desync.
        if let Err(error) = sender.try_send(event) {
            tracing::warn!(%error, "mempool subscription failed, cancelling subscription");
            subscription.take();
        }
    }
}

/// Maintains an ordered index of [`MempoolEvent::TransactionAdded`] events which can be efficiently
/// added and removed.
///
/// This is used to track events which need to be sent on fresh subscriptions.
///
/// The events can be iterated over in chronological order.
#[derive(Default, Clone, Debug, PartialEq)]
struct InflightTransactions {
    /// [`MempoolEvent::TransactionAdded`] events which are still inflight i.e. have not been
    /// committed or reverted.
    ///
    /// These events need to be transmitted when a subscription is started, since the subscriber
    /// only has the committed state.
    ///
    /// A [`BTreeMap`] is used to maintain event ordering while allowing for efficient removals of
    /// committed or reverted transactions.
    ///
    /// The key is auto-incremented on each new insert to support this event ordering.
    ///
    /// A reverse lookup index is maintained in `index`.
    txs: BTreeMap<u64, MempoolEvent>,

    /// A reverse lookup index for `txs` which allows for efficient removal of
    /// committed or reverted events.
    index: BTreeMap<TransactionId, u64>,
}

impl InflightTransactions {
    /// Adds a new transaction event to the tracker.
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - the event is not a [`MempoolEvent::TransactionAdded`], or
    /// - the event already exists
    fn insert(&mut self, tx: MempoolEvent) {
        let MempoolEvent::TransactionAdded { id, .. } = &tx else {
            panic!("Cannot submit a non-tx event to inflight transaction event tracker");
        };

        let idx = self.txs.last_key_value().map(|(&k, _v)| k + 1).unwrap_or_default();
        assert!(
            self.index.insert(*id, idx).is_none(),
            "transaction event already exists in tracker"
        );
        self.txs.insert(idx, tx);
    }

    /// Removes a transaction from the tracker.
    ///
    /// # Panics
    ///
    /// Panics if the transaction was not being tracked.
    fn remove(&mut self, tx: &TransactionId) {
        let idx = self.index.remove(tx).expect("transaction to remove should be tracked");
        self.txs.remove(&idx);
    }

    /// An iterator over all transaction events in the order they were added.
    fn iter(&self) -> impl Iterator<Item = &MempoolEvent> {
        self.txs.values()
    }

    /// The number of transaction events.
    fn len(&self) -> usize {
        self.txs.len()
    }
}
