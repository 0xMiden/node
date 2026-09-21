use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use anyhow::{Context, Result};
use miden_protocol::account::{Account, AccountId};
use miden_protocol::block::account_tree::AccountWitness;
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::note::{Note, NoteId, NoteTag, Nullifier};
use miden_protocol::transaction::{PartialBlockchain, ProvenTransaction};
use miden_testing::MockChain;
use tokio::sync::{Mutex, Notify};

use super::Fixture;
use crate::node::{FundingNode, SyncedNotes};

#[derive(Clone, Copy)]
pub enum Submission {
    Commit,
    CommitAndLoseReply,
    LoseReply,
    Reject,
}

#[derive(Clone)]
pub struct MockNode {
    pub chain: Arc<Mutex<MockChain>>,
    pub submissions: Arc<Mutex<Vec<ProvenTransaction>>>,
    pub outcomes: Arc<Mutex<VecDeque<Submission>>>,
    pub fail_note_fetch: Arc<AtomicBool>,
    pub fail_nullifier_sync: Arc<AtomicBool>,
    pub duplicate_records: Arc<AtomicBool>,
    pub extra_records: Arc<Mutex<Vec<(BlockNumber, Note)>>>,
    pub spent: Arc<Mutex<Vec<(BlockNumber, Nullifier)>>>,
    reads: Arc<AtomicUsize>,
    read: Arc<Notify>,
}

impl MockNode {
    pub fn new(fixture: &Fixture) -> Self {
        Self {
            chain: fixture.chain.clone(),
            submissions: Arc::default(),
            outcomes: Arc::default(),
            fail_note_fetch: Arc::default(),
            fail_nullifier_sync: Arc::default(),
            duplicate_records: Arc::default(),
            extra_records: Arc::default(),
            spent: Arc::default(),
            reads: Arc::default(),
            read: Arc::default(),
        }
    }

    pub async fn wait_for_reads(&self, count: usize) {
        loop {
            let read = self.read.notified();
            if self.reads.load(Ordering::Relaxed) >= count {
                return;
            }
            read.await;
        }
    }
}

#[tonic::async_trait]
impl FundingNode for MockNode {
    async fn tip_chain_state(&self) -> Result<(BlockHeader, PartialBlockchain)> {
        let chain = self.chain.lock().await;
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.read.notify_one();
        Ok((chain.latest_block_header(), chain.latest_partial_blockchain()))
    }

    async fn public_account(
        &self,
        account_id: AccountId,
        _block_num: BlockNumber,
    ) -> Result<(Account, AccountWitness)> {
        let chain = self.chain.lock().await;
        let account = chain.committed_account(account_id)?.clone();
        let witness = chain
            .account_witnesses([account_id])
            .remove(&account_id)
            .context("the account must have a witness")?;
        Ok((account, witness))
    }

    async fn sync_note_ids(&self, tag: NoteTag, from_block: BlockNumber) -> Result<SyncedNotes> {
        let chain = self.chain.lock().await;
        let mut note_ids: Vec<_> = chain
            .committed_notes()
            .values()
            .filter(|record| {
                record.metadata().tag() == tag
                    && record.inclusion_proof().location().block_num() >= from_block
            })
            .map(miden_testing::MockChainNote::id)
            .collect();
        note_ids.extend(
            self.extra_records
                .lock()
                .await
                .iter()
                .filter(|(block, note)| *block >= from_block && note.metadata().tag() == tag)
                .map(|(_, note)| note.id()),
        );
        Ok(SyncedNotes {
            note_ids,
            last_checked_block: chain.latest_block_header().block_num(),
        })
    }

    async fn get_public_notes_by_id(&self, note_ids: &[NoteId]) -> Result<Vec<Note>> {
        if self.fail_note_fetch.swap(false, Ordering::Relaxed) {
            return Err(tonic::Status::unavailable("temporary note fetch failure").into());
        }
        let chain = self.chain.lock().await;
        let mut notes: Vec<_> = chain
            .committed_notes()
            .values()
            .filter(|record| note_ids.contains(&record.id()))
            .filter_map(miden_testing::MockChainNote::note)
            .cloned()
            .collect();
        notes.extend(
            self.extra_records
                .lock()
                .await
                .iter()
                .filter(|(_, note)| note_ids.contains(&note.id()))
                .map(|(_, note)| note.clone()),
        );
        if self.duplicate_records.load(Ordering::Relaxed) {
            notes.extend(notes.clone());
        }
        Ok(notes)
    }

    async fn sync_nullifiers(
        &self,
        nullifiers: &[Nullifier],
        from_block: BlockNumber,
    ) -> Result<HashSet<Nullifier>> {
        if self.fail_nullifier_sync.swap(false, Ordering::Relaxed) {
            return Err(tonic::Status::unavailable("temporary nullifier fetch failure").into());
        }
        let chain = self.chain.lock().await;
        let mut spent: HashSet<_> = nullifiers
            .iter()
            .copied()
            .filter(|nullifier| chain.is_note_consumed(nullifier))
            .collect();
        spent.extend(
            self.spent
                .lock()
                .await
                .iter()
                .filter(|(block, nullifier)| *block >= from_block && nullifiers.contains(nullifier))
                .map(|(_, nullifier)| *nullifier),
        );
        Ok(spent)
    }

    async fn submit(
        &self,
        transaction: &ProvenTransaction,
        _transaction_inputs: &[u8],
    ) -> Result<BlockNumber> {
        self.submissions.lock().await.push(transaction.clone());
        let outcome = self.outcomes.lock().await.pop_front().unwrap_or(Submission::Commit);
        match outcome {
            Submission::Reject => {
                return Err(tonic::Status::invalid_argument("rejected transaction").into());
            },
            Submission::LoseReply => {
                return Err(tonic::Status::unavailable("lost submission reply").into());
            },
            Submission::Commit | Submission::CommitAndLoseReply => {},
        }
        let mut chain = self.chain.lock().await;
        chain.add_pending_proven_transaction(transaction.clone());
        chain.prove_next_block()?;
        if matches!(outcome, Submission::CommitAndLoseReply) {
            return Err(tonic::Status::unavailable("lost reply after commitment").into());
        }
        Ok(chain.latest_block_header().block_num())
    }
}
