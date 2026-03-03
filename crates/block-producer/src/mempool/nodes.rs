use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::batch::{BatchId, ProvenBatch};
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{NoteHeader, Nullifier};
use miden_protocol::transaction::{InputNoteCommitment, TransactionHeader, TransactionId};

use crate::domain::batch::SelectedBatch;
use crate::domain::transaction::AuthenticatedTransaction;

/// Uniquely identifies a node in the mempool.
///
/// This effectively describes the lifecycle of a transaction in the mempool.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub(super) enum NodeId {
    Transaction(TransactionId),
    // UserBatch(BatchId),
    ProposedBatch(BatchId),
    ProvenBatch(BatchId),
    Block(BlockNumber),
}

/// A node representing a [`AuthenticatedTransaction`] which is waiting for inclusion in a batch.
///
/// Once this is selected for inclusion in a batch it will be moved inside a [`ProposedBatchNode`].
#[derive(Clone, Debug, PartialEq)]
pub(super) struct TransactionNode(Arc<AuthenticatedTransaction>);

impl TransactionNode {
    pub(super) fn new(inner: Arc<AuthenticatedTransaction>) -> Self {
        Self(inner)
    }

    pub(super) fn id(&self) -> TransactionId {
        self.0.id()
    }

    pub(super) fn inner(&self) -> &Arc<AuthenticatedTransaction> {
        &self.0
    }

    pub(super) fn expires_at(&self) -> BlockNumber {
        self.0.expires_at()
    }
}

/// Represents a batch which has been proposed by the mempool and which is undergoing proving.
///
/// Once proven it transitions to a [`ProvenBatchNode`].
#[derive(Clone, Debug, PartialEq)]
pub(super) struct ProposedBatchNode(SelectedBatch);

impl ProposedBatchNode {
    pub(super) fn new(batch: SelectedBatch) -> Self {
        Self(batch)
    }

    pub(super) fn into_proven_batch_node(self, proof: Arc<ProvenBatch>) -> ProvenBatchNode {
        ProvenBatchNode {
            txs: self.0.into_transactions(),
            inner: proof,
        }
    }

    pub(super) fn expires_at(&self) -> BlockNumber {
        self.0.txs().iter().map(|tx| tx.expires_at()).min().unwrap_or_default()
    }

    pub(super) fn batch_id(&self) -> BatchId {
        self.0.id()
    }
}

/// Represents a [`ProvenBatch`] which is waiting for inclusion in a block.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct ProvenBatchNode {
    /// We need to store this in addition to the proven batch because [`ProvenBatch`] erases the
    /// transaction information. We need the original information if we want to rollback the batch
    /// but retain the transactions.
    txs: Vec<Arc<AuthenticatedTransaction>>,
    inner: Arc<ProvenBatch>,
}

impl ProvenBatchNode {
    pub(super) fn tx_headers(&self) -> impl Iterator<Item = &TransactionHeader> {
        self.inner.transactions().as_slice().iter()
    }

    pub(super) fn id(&self) -> BatchId {
        self.inner.id()
    }

    pub(super) fn inner(&self) -> &Arc<ProvenBatch> {
        &self.inner
    }

    pub(super) fn expires_at(&self) -> BlockNumber {
        self.inner.batch_expiration_block_num()
    }
}

/// Represents a block - both committed and in-progress.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct BlockNode {
    txs: Vec<Arc<AuthenticatedTransaction>>,
    batches: Vec<Arc<ProvenBatch>>,
    number: BlockNumber,
    /// Aggregated account updates of all batches.
    account_updates: HashMap<AccountId, (Word, Word)>,
}

impl BlockNode {
    pub(super) fn new(number: BlockNumber) -> Self {
        Self {
            number,
            txs: Vec::default(),
            batches: Vec::default(),
            account_updates: HashMap::default(),
        }
    }

    pub(super) fn push(&mut self, batch: ProvenBatchNode) {
        let ProvenBatchNode { txs, inner: batch } = batch;
        for (account, update) in batch.account_updates() {
            self.account_updates
                .entry(*account)
                .and_modify(|(_, to)| {
                    assert!(
                        to == &update.initial_state_commitment(),
                        "Cannot select batch {} as its initial commitment {} for account {} does \
    not match the current commitment {}",
                        batch.id(),
                        update.initial_state_commitment(),
                        update.account_id(),
                        to
                    );

                    *to = update.final_state_commitment();
                })
                .or_insert((update.initial_state_commitment(), update.final_state_commitment()));
        }

        self.txs.extend(txs);
        self.batches.push(batch);
    }

    pub(super) fn contains(&self, id: BatchId) -> bool {
        self.batches.iter().any(|batch| batch.id() == id)
    }

    pub(super) fn batches(&self) -> &[Arc<ProvenBatch>] {
        &self.batches
    }
}

/// Describes a node's impact on the state.
///
/// This is used to determine what state data is created or consumed by this node.
pub(super) trait Node {
    /// All [`Nullifier`]s created by this node, **including** nullifiers for erased notes. This
    /// may not be strictly necessary but it removes having to worry about reverting batches and
    /// blocks with erased notes -- since these would otherwise have different state impact than
    /// the transactions within them.
    fn nullifiers(&self) -> Box<dyn Iterator<Item = Nullifier> + '_>;

    /// All output note commitments created by this node, **including** erased notes. This may not
    /// be strictly necessary but it removes having to worry about reverting batches and blocks
    /// with erased notes -- since these would otherwise have different state impact than the
    /// transactions within them.
    fn output_note_commitments(&self) -> Box<dyn Iterator<Item = Word> + '_>;
    fn unauthenticated_note_commitments(&self) -> Box<dyn Iterator<Item = Word> + '_>;
    /// The account state commitment updates caused by this node.
    ///
    /// Output tuple represents each updates `(account ID, initial commitment, final commitment)`.
    ///
    /// Updates must be aggregates i.e. only a single account ID update allowed.
    fn account_updates(&self) -> Box<dyn Iterator<Item = (AccountId, Word, Word)> + '_>;
    fn transactions(&self) -> Box<dyn Iterator<Item = &Arc<AuthenticatedTransaction>> + '_>;

    fn id(&self) -> NodeId;
}

impl Node for TransactionNode {
    fn nullifiers(&self) -> Box<dyn Iterator<Item = Nullifier> + '_> {
        Box::new(self.0.nullifiers())
    }

    fn output_note_commitments(&self) -> Box<dyn Iterator<Item = Word> + '_> {
        Box::new(self.0.output_note_commitments())
    }

    fn unauthenticated_note_commitments(&self) -> Box<dyn Iterator<Item = Word> + '_> {
        Box::new(self.0.unauthenticated_note_commitments())
    }

    fn account_updates(&self) -> Box<dyn Iterator<Item = (AccountId, Word, Word)> + '_> {
        let update = self.0.account_update();
        Box::new(std::iter::once((
            update.account_id(),
            update.initial_state_commitment(),
            update.final_state_commitment(),
        )))
    }

    fn transactions(&self) -> Box<dyn Iterator<Item = &Arc<AuthenticatedTransaction>> + '_> {
        Box::new(std::iter::once(&self.0))
    }

    fn id(&self) -> NodeId {
        NodeId::Transaction(self.id())
    }
}

impl Node for ProposedBatchNode {
    fn nullifiers(&self) -> Box<dyn Iterator<Item = Nullifier> + '_> {
        Box::new(self.0.txs().iter().flat_map(|tx| tx.nullifiers()))
    }

    fn output_note_commitments(&self) -> Box<dyn Iterator<Item = Word> + '_> {
        Box::new(self.0.txs().iter().flat_map(|tx| tx.output_note_commitments()))
    }

    fn unauthenticated_note_commitments(&self) -> Box<dyn Iterator<Item = Word> + '_> {
        Box::new(self.0.txs().iter().flat_map(|tx| tx.unauthenticated_note_commitments()))
    }

    fn account_updates(&self) -> Box<dyn Iterator<Item = (AccountId, Word, Word)> + '_> {
        Box::new(self.0.account_updates())
    }

    fn transactions(&self) -> Box<dyn Iterator<Item = &Arc<AuthenticatedTransaction>> + '_> {
        Box::new(self.0.txs().iter())
    }

    fn id(&self) -> NodeId {
        NodeId::ProposedBatch(self.0.id())
    }
}

impl Node for ProvenBatchNode {
    fn nullifiers(&self) -> Box<dyn Iterator<Item = Nullifier> + '_> {
        Box::new(
            self.tx_headers()
                .flat_map(|tx| tx.input_notes().iter().map(InputNoteCommitment::nullifier)),
        )
    }

    fn output_note_commitments(&self) -> Box<dyn Iterator<Item = Word> + '_> {
        Box::new(
            self.tx_headers()
                .flat_map(|tx| tx.output_notes().iter().map(NoteHeader::commitment)),
        )
    }

    fn unauthenticated_note_commitments(&self) -> Box<dyn Iterator<Item = Word> + '_> {
        Box::new(
            self.inner
                .input_notes()
                .iter()
                .filter_map(|note| note.header())
                .map(NoteHeader::commitment),
        )
    }

    fn account_updates(&self) -> Box<dyn Iterator<Item = (AccountId, Word, Word)> + '_> {
        Box::new(self.inner.account_updates().values().map(|update| {
            (
                update.account_id(),
                update.initial_state_commitment(),
                update.final_state_commitment(),
            )
        }))
    }

    fn transactions(&self) -> Box<dyn Iterator<Item = &Arc<AuthenticatedTransaction>> + '_> {
        Box::new(self.txs.iter())
    }

    fn id(&self) -> NodeId {
        NodeId::ProvenBatch(self.id())
    }
}

impl Node for BlockNode {
    fn nullifiers(&self) -> Box<dyn Iterator<Item = Nullifier> + '_> {
        Box::new(self.txs.iter().flat_map(|tx| tx.nullifiers()))
    }

    fn output_note_commitments(&self) -> Box<dyn Iterator<Item = Word> + '_> {
        Box::new(
            self.txs
                .iter()
                .flat_map(|tx: &Arc<AuthenticatedTransaction>| tx.output_note_commitments()),
        )
    }

    fn unauthenticated_note_commitments(&self) -> Box<dyn Iterator<Item = Word> + '_> {
        Box::new(self.batches.iter().flat_map(|batch| {
            batch
                .input_notes()
                .iter()
                .filter_map(|note| note.header().map(NoteHeader::commitment))
        }))
    }

    fn account_updates(&self) -> Box<dyn Iterator<Item = (AccountId, Word, Word)> + '_> {
        Box::new(self.account_updates.iter().map(|(account, (from, to))| (*account, *from, *to)))
    }

    fn transactions(&self) -> Box<dyn Iterator<Item = &Arc<AuthenticatedTransaction>> + '_> {
        Box::new(self.txs.iter())
    }

    fn id(&self) -> NodeId {
        NodeId::Block(self.number)
    }
}

/// Contains the current nodes of the state DAG.
///
/// Nodes are purposefully not stored as a single collection since we often want to iterate
/// through specific node types e.g. all available transactions.
///
/// This data _must_ be kept in sync with the [`InflightState's`] [`NodeIds`] since these are
/// used as the edges of the graph.
#[derive(Clone, Debug, PartialEq, Default)]
pub(super) struct Nodes {
    // Nodes in the DAG
    pub(super) txs: HashMap<TransactionId, TransactionNode>,
    // user_batches: HashMap<BatchId, ProvenBatchNode>,
    pub(super) proposed_batches: HashMap<BatchId, ProposedBatchNode>,
    pub(super) proven_batches: HashMap<BatchId, ProvenBatchNode>,
    pub(super) proposed_block: Option<(BlockNumber, BlockNode)>,
    pub(super) committed_blocks: VecDeque<(BlockNumber, BlockNode)>,
}

impl Nodes {
    pub(super) fn oldest_committed_block(&self) -> Option<BlockNumber> {
        self.committed_blocks.front().map(|(number, _)| *number)
    }

    pub(super) fn inject_telemetry(&self, span: &tracing::Span) {
        use miden_node_utils::tracing::OpenTelemetrySpanExt;

        span.set_attribute("mempool.transactions.uncommitted", self.uncommitted_tx_count());
        span.set_attribute("mempool.transactions.unbatched", self.txs.len());
        span.set_attribute("mempool.batches.proposed", self.proposed_batches.len());
        span.set_attribute("mempool.batches.proven", self.proven_batches.len());
    }

    pub(super) fn uncommitted_tx_count(&self) -> usize {
        self.txs.len()
            + self.proposed_batches.values().map(|b| b.0.txs().len()).sum::<usize>()
            + self.proven_batches.values().map(|b| b.txs.len()).sum::<usize>()
            + self.proposed_block.as_ref().map(|b| b.1.txs.len()).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use miden_protocol::batch::BatchAccountUpdate;
    use miden_protocol::transaction::{InputNotes, OrderedTransactionHeaders};

    use super::*;
    use crate::test_utils::MockProvenTxBuilder;

    #[test]
    fn proposed_batch_aggregates_account_updates() {
        let mut batch = SelectedBatch::builder();
        let txs = MockProvenTxBuilder::sequential();

        let account = txs.first().unwrap().account_id();
        let from = txs.first().unwrap().account_update().initial_state_commitment();
        let to = txs.last().unwrap().account_update().final_state_commitment();
        let expected = std::iter::once((account, from, to));

        for tx in txs {
            batch.push(tx);
        }
        let batch = ProposedBatchNode::new(batch.build());

        itertools::assert_equal(batch.account_updates(), expected);
    }

    #[test]
    fn block_aggregates_account_updates() {
        // We map each tx into its own batch.
        //
        // This let's us trivially know what the expected aggregate block account update should be.
        let txs = MockProvenTxBuilder::sequential();
        let account = txs.first().unwrap().account_id();
        let from = txs.first().unwrap().account_update().initial_state_commitment();
        let to = txs.last().unwrap().account_update().final_state_commitment();
        let expected = std::iter::once((account, from, to));

        let mut block = BlockNode::new(BlockNumber::default());

        for tx in txs {
            let mut batch = SelectedBatch::builder();
            batch.push(tx.clone());
            let batch = batch.build();
            let batch = ProposedBatchNode::new(batch);

            let account_update = BatchAccountUpdate::from_transaction(tx.raw_proven_transaction());

            let tx_header = TransactionHeader::from(tx.raw_proven_transaction());
            let proven_batch = ProvenBatch::new(
                batch.batch_id(),
                Word::default(),
                BlockNumber::default(),
                BTreeMap::from([(account_update.account_id(), account_update)]),
                InputNotes::default(),
                Vec::default(),
                BlockNumber::MAX,
                OrderedTransactionHeaders::new_unchecked(vec![tx_header]),
            )
            .unwrap();

            let batch = batch.into_proven_batch_node(Arc::new(proven_batch));
            block.push(batch);
        }

        itertools::assert_equal(block.account_updates(), expected);
    }
}
