//! Renders the explorer card. Compares the explorer's tip against the RPC's tip (passed in by the
//! dispatcher) and surfaces a warning banner past `EXPLORER_LAG_TOLERANCE` blocks of drift.

use maud::{Markup, html};

use super::super::helpers::{commitment_or_dash, format_timestamp, metric_row, num_or_dash};
use crate::status::ExplorerStatusDetails;

/// Maximum allowed block delta between the explorer's tip and the RPC's tip before we surface a
/// warning banner on the explorer card. ~1 minute at current block cadence.
const EXPLORER_LAG_TOLERANCE: u64 = 20;

pub(in crate::view) fn render_explorer(
    stats: &ExplorerStatusDetails,
    rpc_chain_tip: Option<u32>,
    healthy: bool,
) -> Markup {
    let block_number_str = if healthy {
        stats.block_number.to_string()
    } else {
        "-".to_string()
    };
    let rpc_chain_tip_str = match rpc_chain_tip {
        Some(t) if healthy => t.to_string(),
        _ => "-".to_string(),
    };
    let block_time = if healthy {
        format_timestamp(stats.timestamp)
    } else {
        "-".to_string()
    };

    let delta_warning = rpc_chain_tip.filter(|_| healthy).and_then(|tip| {
        let tip = u64::from(tip);
        let (direction, magnitude) = if stats.block_number >= tip {
            ("ahead", stats.block_number - tip)
        } else {
            ("behind", tip - stats.block_number)
        };
        if magnitude > EXPLORER_LAG_TOLERANCE {
            Some(format!("Explorer tip is {magnitude} blocks {direction}"))
        } else {
            None
        }
    });

    html! {
        div class="service-details" {
            div class="nested-status" {
                strong { "Explorer:" }
                (metric_row("Block Height:", &block_number_str))
                (metric_row("RPC Chain Tip:", &rpc_chain_tip_str))
                (metric_row("Block Time:", &block_time))
                div class="metric-row" {
                    span class="metric-label" { "Block Commitment:" }
                    span class="metric-value" {
                        (commitment_or_dash(&stats.block_commitment, "block commitment", healthy))
                    }
                }
                div class="metric-row" {
                    span class="metric-label" { "Chain Commitment:" }
                    span class="metric-value" {
                        (commitment_or_dash(&stats.chain_commitment, "chain commitment", healthy))
                    }
                }
                div class="metric-row" {
                    span class="metric-label" { "Proof Commitment:" }
                    span class="metric-value" {
                        (commitment_or_dash(&stats.proof_commitment, "proof commitment", healthy))
                    }
                }
                (metric_row(
                    "Transactions:",
                    &num_or_dash(stats.number_of_transactions, healthy),
                ))
                (metric_row("Nullifiers:", &num_or_dash(stats.number_of_nullifiers, healthy)))
                (metric_row("Notes:", &num_or_dash(stats.number_of_notes, healthy)))
                (metric_row(
                    "Account Updates:",
                    &num_or_dash(stats.number_of_account_updates, healthy),
                ))
            }
        }
        @if let Some(warning) = delta_warning {
            div class="warning-banner" {
                div class="metric-row" {
                    span class="metric-label" { "Explorer vs RPC" }
                }
                div class="warning-text" { (warning) }
            }
        }
    }
}
