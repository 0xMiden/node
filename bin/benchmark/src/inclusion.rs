//! Post-submission inclusion scan.
//!
//! `scan_with_drain` is the one-shot watcher: it polls the chain past a
//! starting height, scans each new block for the txs we submitted, and
//! exits as soon as every submitted tx has been seen on-chain — falling
//! back to a `max_blocks` bound if some submissions never land. The result
//! carries per-block hit counts plus the scan span used to derive the
//! average block interval.

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use miden_node_proto::clients::RpcClient;
use miden_node_proto::generated as proto;
use miden_node_proto::generated::rpc::BlockHeaderByNumberRequest;
use miden_protocol::block::{BlockHeader, SignedBlock};
use miden_protocol::transaction::TransactionId;
use miden_protocol::utils::serde::Deserializable;

/// One scanned block that contained at least one of our txs. Empty blocks in the scan range are not
/// represented here.
#[derive(Debug, Clone, Copy)]
pub(crate) struct BlockHit {
    /// On-chain block number.
    pub(crate) block_num: u32,
    /// Unix-seconds timestamp from the block header.
    pub(crate) block_ts: u32,
    /// Number of our txs included in this block.
    pub(crate) hit_count: u32,
}

#[derive(Debug)]
pub(crate) struct InclusionResult {
    pub(crate) submitted_count: u64,
    pub(crate) included_count: u64,
    /// One entry per block in the scan range that included any of our txs, in scan order.
    /// Throughput metrics are derived from this list plus the block interval inferred from the scan
    /// span (see [`InclusionResult::derived_block_interval`]).
    pub(crate) per_block_hits: Vec<BlockHit>,
    /// For each successfully submitted tx that landed in a block: the elapsed time from RPC ack to
    /// that block's header timestamp.
    pub(crate) inclusion_latencies: Vec<Duration>,
    /// Number of blocks the inclusion scan successfully read headers for.
    pub(crate) scanned_block_count: u32,
    /// Header timestamps of the first and last successfully scanned blocks (unix seconds). Together
    /// with `scanned_block_count`, used to derive the block interval at print time.
    pub(crate) scanned_first_ts: u32,
    pub(crate) scanned_last_ts: u32,
}

impl InclusionResult {
    /// Derive the average block interval from the scan span. Returns `None` when the scan touched
    /// fewer than two blocks or when all scanned headers share the same 1-second-resolution
    /// timestamp (sub-second cadence), in which case the bench cannot determine the interval from
    /// headers alone.
    pub(crate) fn derived_block_interval(&self) -> Option<Duration> {
        if self.scanned_block_count < 2 || self.scanned_last_ts <= self.scanned_first_ts {
            return None;
        }
        let span_secs = u64::from(self.scanned_last_ts - self.scanned_first_ts);
        let intervals = u64::from(self.scanned_block_count - 1);
        // f64 keeps the fractional seconds when the cadence is finer than 1s *and* the scan crosses
        // enough one-second boundaries.
        #[expect(
            clippy::cast_precision_loss,
            reason = "block counts and timestamp deltas are tiny in practice"
        )]
        let interval_secs = (span_secs as f64) / (intervals as f64);
        Some(Duration::from_secs_f64(interval_secs))
    }
}

/// Watch the chain advance past `start_height` and scan each new block for our submitted txs as it
/// lands. Stops as soon as every entry in `ack_by_id` has been matched (early-exit), or after
/// `max_blocks` blocks past `start_height` have been scanned without draining (timeout) — whichever
/// comes first. Returns the final scanned block number alongside the inclusion stats; if early-exit
/// fires, the returned `h_final` is the block that completed the drain.
#[expect(
    clippy::too_many_lines,
    reason = "polling + per-block deserialization + tx-id matching is intentionally inline; \
              the alternative is to thread eight pieces of mutable state through a helper, \
              which obscures the read flow without changing the logic"
)]
pub(crate) async fn scan_with_drain(
    mut client: RpcClient,
    start_height: u32,
    max_blocks: u32,
    mut ack_by_id: HashMap<TransactionId, SystemTime>,
) -> (u32, InclusionResult) {
    let submitted_count = ack_by_id.len() as u64;
    let mut included_count: u64 = 0;
    let mut per_block_hits: Vec<BlockHit> = Vec::new();
    let mut inclusion_latencies: Vec<Duration> = Vec::new();
    let mut scanned_block_count: u32 = 0;
    let mut scanned_first_ts: u32 = 0;
    let mut scanned_last_ts: u32 = 0;

    let max_target = start_height.saturating_add(max_blocks);
    let mut next_block = start_height + 1;
    let mut last_seen_height = start_height;
    let mut h_final = start_height;

    'outer: loop {
        // Refresh the chain tip and announce changes.
        let tip = current_block_height(client.clone()).await;
        if tip != last_seen_height {
            println!("  block height: {tip}");
            last_seen_height = tip;
        }

        // Scan every unwatched block, capped at the max-bound target.
        let scan_to = tip.min(max_target);
        while next_block <= scan_to {
            let request = proto::blockchain::BlockRequest {
                block_num: next_block,
                include_proof: None,
            };
            let response = match client.get_block_by_number(request).await {
                Ok(r) => r.into_inner(),
                Err(status) => {
                    eprintln!(
                        "  warning: get_block_by_number({next_block}) failed: {status} \
                         — skipping this block in the inclusion scan"
                    );
                    next_block += 1;
                    continue;
                },
            };
            let Some(bytes) = response.block else {
                next_block += 1;
                continue;
            };
            let signed_block = match SignedBlock::read_from_bytes(&bytes) {
                Ok(sb) => sb,
                Err(err) => {
                    eprintln!(
                        "  warning: failed to deserialize SignedBlock for block {next_block}: {err}"
                    );
                    next_block += 1;
                    continue;
                },
            };

            let block_ts = signed_block.header().timestamp();
            let block_ts_system = UNIX_EPOCH + Duration::from_secs(u64::from(block_ts));

            // Track scan span so we can derive the block interval at print time.
            if scanned_block_count == 0 {
                scanned_first_ts = block_ts;
            }
            scanned_last_ts = block_ts;
            scanned_block_count += 1;

            let mut hits_in_this_block: u32 = 0;
            for header in signed_block.body().transactions().as_slice() {
                if let Some(ack_at) = ack_by_id.remove(&header.id()) {
                    hits_in_this_block += 1;
                    included_count += 1;
                    // Block timestamps have 1-second resolution and may round down past the ack
                    // instant; clamp negative deltas to zero.
                    let latency = block_ts_system.duration_since(ack_at).unwrap_or_default();
                    inclusion_latencies.push(latency);
                }
            }

            if hits_in_this_block > 0 {
                per_block_hits.push(BlockHit {
                    block_num: next_block,
                    block_ts,
                    hit_count: hits_in_this_block,
                });
            }

            h_final = next_block;
            next_block += 1;

            // Early exit: pending set drained — every submitted tx is on chain.
            if ack_by_id.is_empty() {
                println!(
                    "  all {submitted_count} submitted tx(s) included by block {h_final}; \
                     stopping scan early"
                );
                break 'outer;
            }
        }

        // Hit the safety bound but still have pending txs. Stop and report what we have; the
        // unaccounted-for txs will show as drop in the summary.
        if next_block > max_target {
            println!(
                "  reached max wait of {max_blocks} blocks past height {start_height}; \
                 stopping with {} tx(s) still pending",
                ack_by_id.len(),
            );
            break;
        }

        // Pace the polling.
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let inclusion = InclusionResult {
        submitted_count,
        included_count,
        per_block_hits,
        inclusion_latencies,
        scanned_block_count,
        scanned_first_ts,
        scanned_last_ts,
    };
    (h_final, inclusion)
}

pub(crate) async fn current_block_height(mut client: RpcClient) -> u32 {
    let response = client
        .get_block_header_by_number(BlockHeaderByNumberRequest {
            block_num: None,
            include_mmr_proof: None,
        })
        .await
        .expect("failed to fetch latest block header")
        .into_inner();
    let header: BlockHeader = response
        .block_header
        .expect("no block header in response")
        .try_into()
        .expect("failed to decode block header");
    header.block_num().as_u32()
}
