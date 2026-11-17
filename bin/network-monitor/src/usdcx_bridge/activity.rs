//! Deposits and withdrawals of the `USDCx` faucet over the last 24 hours of chain time.
//!
//! The tracker follows the faucet's transactions with `SyncTransactions` and keeps the bridge
//! events of the window in memory, so a restart rebuilds the window from chain history.
//!
//! Faucet transactions are network transactions, which carry the full header of every consumed
//! note. The faucet's mint and burn policies only accept notes with a `USDCx` mint or burn
//! attachment, so the attachment scheme of a consumed note identifies a deposit or a withdrawal
//! without fetching the note. A transaction can consume several notes, so each note is one event.

use std::collections::{BTreeMap, VecDeque};
use std::time::Duration;

use anyhow::{Context, Result};
use miden_node_proto::DecodeMessageExt;
use miden_node_proto::clients::RpcClient;
use miden_node_proto::generated::miden::node::v1::{
    BlockRange,
    GetBlockHeaderByNumberRequest,
    SyncTransactionsRequest,
};
use miden_node_tracing::warn;
use miden_protocol::account::AccountId;
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::note::NoteMetadata;
use miden_protocol::transaction::TransactionHeader;
use miden_standards::note::StandardNoteAttachment;
use tokio::time::Instant;

use crate::status::{UsdcxActivityDetails, UsdcxBridgeEvent, UsdcxBridgeEventKind};

/// Length of the activity window, in seconds of chain time.
const WINDOW_SECS: u32 = 24 * 60 * 60;

/// Bridge events of the `USDCx` faucet within the activity window.
#[derive(Default)]
pub(super) struct ActivityTracker {
    faucet_id: Option<AccountId>,
    /// Last block whose transactions have been processed.
    synced_to: Option<BlockNumber>,
    chain_tip: BlockNumber,
    /// Events in the window, in block order.
    events: VecDeque<UsdcxBridgeEvent>,
    latest: Option<UsdcxBridgeEvent>,
}

impl ActivityTracker {
    /// Processes the faucet's transactions up to `tip` and drops events that left the window.
    ///
    /// Processing stops early once `budget` has elapsed, so a long first sync does not hold back
    /// the card. The next call resumes from the last processed block.
    pub async fn sync(
        &mut self,
        rpc: &mut RpcClient,
        faucet_id: AccountId,
        tip: &BlockHeader,
        budget: Duration,
    ) -> Result<()> {
        let deadline = Instant::now() + budget;
        self.prepare(faucet_id, tip.block_num());

        let end = tip.block_num();
        let mut start = self.next_block();
        while start <= end {
            let (events, last_block) = fetch_events(rpc, faucet_id, start, end).await?;
            self.ingest(events, last_block);
            start = last_block + 1;
            if Instant::now() >= deadline {
                break;
            }
        }

        self.prune(tip.timestamp());
        Ok(())
    }

    /// Returns the activity counts, or `None` before the first processed page.
    pub fn details(&self) -> Option<UsdcxActivityDetails> {
        let synced_to = self.synced_to?;
        let count = |kind| self.events.iter().filter(|event| event.kind == kind).count() as u64;
        Some(UsdcxActivityDetails {
            deposits_24h: count(UsdcxBridgeEventKind::Deposit),
            withdrawals_24h: count(UsdcxBridgeEventKind::Withdrawal),
            latest: self.latest.clone(),
            synced_to: synced_to.as_u32(),
            chain_tip: self.chain_tip.as_u32(),
        })
    }

    /// Starts over when the faucet changes or the chain tip falls behind the processed blocks,
    /// which happens after a network reset.
    fn prepare(&mut self, faucet_id: AccountId, tip: BlockNumber) {
        if self.faucet_id != Some(faucet_id) || self.synced_to.is_some_and(|synced| synced > tip) {
            *self = Self {
                faucet_id: Some(faucet_id),
                ..Self::default()
            };
        }
        self.chain_tip = tip;
    }

    /// First block to process.
    ///
    /// The first sync starts one window of seconds below the tip. Block timestamps strictly
    /// increase in whole seconds, so the block produced a window ago is never further back.
    fn next_block(&self) -> BlockNumber {
        self.synced_to.map_or_else(
            || BlockNumber::from(self.chain_tip.as_u32().saturating_sub(WINDOW_SECS)),
            |synced| synced + 1,
        )
    }

    /// Adds the events of a processed range that ends at `synced_to`.
    ///
    /// Events in blocks that were already processed are ignored, so processing a range again does
    /// not count its events twice.
    fn ingest(&mut self, events: Vec<UsdcxBridgeEvent>, synced_to: BlockNumber) {
        let processed = self.synced_to.map(|synced| synced.as_u32());
        for event in events {
            if processed.is_some_and(|processed| event.block_num <= processed) {
                continue;
            }
            self.latest = Some(event.clone());
            self.events.push_back(event);
        }
        self.synced_to = Some(self.synced_to.map_or(synced_to, |synced| synced.max(synced_to)));
    }

    /// Drops events older than one window before `tip_timestamp`.
    fn prune(&mut self, tip_timestamp: u32) {
        let cutoff = u64::from(tip_timestamp.saturating_sub(WINDOW_SECS));
        while self.events.front().is_some_and(|event| event.timestamp < cutoff) {
            self.events.pop_front();
        }
    }
}

/// Returns the bridge events of the faucet's transactions in one page of `start..=end`, and the
/// last block the page covers.
async fn fetch_events(
    rpc: &mut RpcClient,
    faucet_id: AccountId,
    start: BlockNumber,
    end: BlockNumber,
) -> Result<(Vec<UsdcxBridgeEvent>, BlockNumber)> {
    let response = rpc
        .sync_transactions(SyncTransactionsRequest {
            block_range: Some(BlockRange {
                block_from: start.as_u32(),
                block_to: end.as_u32(),
            }),
            account_ids: vec![faucet_id.into()],
        })
        .await
        .context("failed to sync the faucet transactions")?
        .into_inner();

    let last_block: BlockNumber = response
        .pagination_info
        .context("the sync_transactions response has no pagination information")?
        .block_num
        .into();
    anyhow::ensure!(
        (start..=end).contains(&last_block),
        "the node answered a transaction sync from {start} to {end} with block {last_block}",
    );

    let mut timestamps = BTreeMap::new();
    let mut events = Vec::new();
    for record in response.transactions {
        let block_num = BlockNumber::from(record.block_num);
        let header: TransactionHeader = record
            .header
            .context("a transaction record has no header")?
            .decode_and_build_unchecked()
            .context("failed to decode a transaction header")?;

        let unclassified =
            header.input_notes().iter().filter(|note| note.header().is_none()).count();
        if unclassified > 0 {
            warn!(
                "Faucet transaction consumed notes without headers; they are not counted",
                transaction.id = header.id(),
                note.count = unclassified
            );
        }

        let kinds = bridge_kinds(&header);
        if kinds.is_empty() {
            continue;
        }
        let timestamp = if let Some(timestamp) = timestamps.get(&block_num) {
            *timestamp
        } else {
            let timestamp = block_timestamp(rpc, block_num).await?;
            timestamps.insert(block_num, timestamp);
            timestamp
        };
        events.extend(kinds.into_iter().map(|kind| UsdcxBridgeEvent {
            kind,
            block_num: block_num.as_u32(),
            timestamp,
            transaction_id: header.id().to_hex(),
        }));
    }
    Ok((events, last_block))
}

/// Fetches the timestamp of `block`.
async fn block_timestamp(rpc: &mut RpcClient, block: BlockNumber) -> Result<u64> {
    let header: BlockHeader = rpc
        .get_block_header_by_number(GetBlockHeaderByNumberRequest {
            block_num: Some(block.as_u32()),
            include_mmr_proof: None,
            include_protocol_config: None,
        })
        .await
        .with_context(|| format!("failed to get the header of block {block}"))?
        .into_inner()
        .block_header
        .with_context(|| format!("the node returned no header for block {block}"))?
        .decode_and_build_unchecked()
        .with_context(|| format!("failed to decode the header of block {block}"))?;
    anyhow::ensure!(
        header.block_num() == block,
        "the node returned block {} for block {block}",
        header.block_num()
    );
    Ok(u64::from(header.timestamp()))
}

/// Returns one event kind for each deposit or withdrawal note the transaction consumed.
fn bridge_kinds(header: &TransactionHeader) -> Vec<UsdcxBridgeEventKind> {
    header
        .input_notes()
        .iter()
        .filter_map(|note| note.header())
        .filter_map(|note| bridge_kind(note.metadata()))
        .collect()
}

/// Identifies deposit and withdrawal notes by their `USDCx` attachment.
fn bridge_kind(metadata: &NoteMetadata) -> Option<UsdcxBridgeEventKind> {
    let deposit = StandardNoteAttachment::UsdcxMint.attachment_scheme();
    let withdrawal = StandardNoteAttachment::UsdcxBurn.attachment_scheme();
    metadata
        .attachment_headers()
        .iter()
        .find_map(|attachment| match attachment.scheme() {
            Some(scheme) if scheme == deposit => Some(UsdcxBridgeEventKind::Deposit),
            Some(scheme) if scheme == withdrawal => Some(UsdcxBridgeEventKind::Withdrawal),
            _ => None,
        })
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::Word;
    use miden_protocol::note::{
        NoteAttachment,
        NoteAttachmentScheme,
        NoteAttachments,
        NoteType,
        PartialNoteMetadata,
    };
    use miden_protocol::testing::account_id::{
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
    };

    use super::*;

    fn faucet() -> AccountId {
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into().unwrap()
    }

    fn metadata(schemes: &[NoteAttachmentScheme]) -> NoteMetadata {
        let sender: AccountId =
            ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE.try_into().unwrap();
        let attachments = NoteAttachments::new(
            schemes
                .iter()
                .map(|scheme| NoteAttachment::with_word(*scheme, Word::empty()))
                .collect(),
        )
        .unwrap();
        NoteMetadata::new(PartialNoteMetadata::new(sender, NoteType::Public), &attachments)
    }

    fn event(kind: UsdcxBridgeEventKind, block_num: u32, timestamp: u64) -> UsdcxBridgeEvent {
        UsdcxBridgeEvent {
            kind,
            block_num,
            timestamp,
            transaction_id: format!("0x{block_num:064x}"),
        }
    }

    fn tracker_at(tip: u32) -> ActivityTracker {
        let mut tracker = ActivityTracker::default();
        tracker.prepare(faucet(), BlockNumber::from(tip));
        tracker
    }

    #[test]
    fn usdcx_attachments_identify_deposits_and_withdrawals() {
        let routing = StandardNoteAttachment::NetworkAccountTarget.attachment_scheme();
        let mint = StandardNoteAttachment::UsdcxMint.attachment_scheme();
        let burn = StandardNoteAttachment::UsdcxBurn.attachment_scheme();

        assert_eq!(bridge_kind(&metadata(&[mint, routing])), Some(UsdcxBridgeEventKind::Deposit));
        assert_eq!(
            bridge_kind(&metadata(&[routing, burn])),
            Some(UsdcxBridgeEventKind::Withdrawal)
        );
        // Admin notes only carry the routing attachment, and fee notes carry none.
        assert_eq!(bridge_kind(&metadata(&[routing])), None);
        assert_eq!(bridge_kind(&metadata(&[])), None);
    }

    #[test]
    fn counts_every_event_in_the_window() {
        let mut tracker = tracker_at(100);
        tracker.ingest(
            vec![
                event(UsdcxBridgeEventKind::Deposit, 10, 1_000),
                event(UsdcxBridgeEventKind::Deposit, 10, 1_000),
                event(UsdcxBridgeEventKind::Withdrawal, 12, 1_006),
            ],
            BlockNumber::from(100),
        );

        let details = tracker.details().unwrap();
        assert_eq!(details.deposits_24h, 2);
        assert_eq!(details.withdrawals_24h, 1);
        assert_eq!(details.latest.unwrap().block_num, 12);
        assert_eq!(details.synced_to, 100);
    }

    #[test]
    fn reprocessed_blocks_are_not_counted_twice() {
        let mut tracker = tracker_at(100);
        let page = vec![event(UsdcxBridgeEventKind::Deposit, 10, 1_000)];
        tracker.ingest(page.clone(), BlockNumber::from(50));
        tracker.ingest(page, BlockNumber::from(50));

        assert_eq!(tracker.details().unwrap().deposits_24h, 1);
    }

    #[test]
    fn events_leave_the_window_but_the_latest_is_kept() {
        let mut tracker = tracker_at(100_000);
        let day = u64::from(WINDOW_SECS);
        tracker.ingest(
            vec![
                event(UsdcxBridgeEventKind::Deposit, 10, 1_000),
                event(UsdcxBridgeEventKind::Withdrawal, 20, 2_000),
            ],
            BlockNumber::from(100_000),
        );

        // At exactly one window after the deposit, the deposit is still in the window.
        tracker.prune(u32::try_from(1_000 + day).unwrap());
        assert_eq!(tracker.details().unwrap().deposits_24h, 1);

        tracker.prune(u32::try_from(3_000 + day).unwrap());
        let details = tracker.details().unwrap();
        assert_eq!(details.deposits_24h, 0);
        assert_eq!(details.withdrawals_24h, 0);
        assert_eq!(details.latest.unwrap().kind, UsdcxBridgeEventKind::Withdrawal);
    }

    #[test]
    fn first_sync_starts_one_window_below_the_tip() {
        assert_eq!(tracker_at(100_000).next_block(), BlockNumber::from(100_000 - WINDOW_SECS));
        assert_eq!(tracker_at(100).next_block(), BlockNumber::GENESIS);

        let mut tracker = tracker_at(100_000);
        tracker.ingest(Vec::new(), BlockNumber::from(99_990));
        assert_eq!(tracker.next_block(), BlockNumber::from(99_991));
    }

    #[test]
    fn faucet_change_or_tip_regression_starts_over() {
        let mut tracker = tracker_at(100);
        tracker
            .ingest(vec![event(UsdcxBridgeEventKind::Deposit, 10, 1_000)], BlockNumber::from(100));

        tracker.prepare(faucet(), BlockNumber::from(50));
        assert!(tracker.details().is_none());

        tracker
            .ingest(vec![event(UsdcxBridgeEventKind::Deposit, 10, 1_000)], BlockNumber::from(50));
        let other_faucet = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1.try_into().unwrap();
        tracker.prepare(other_faucet, BlockNumber::from(60));
        assert!(tracker.details().is_none());
    }
}
