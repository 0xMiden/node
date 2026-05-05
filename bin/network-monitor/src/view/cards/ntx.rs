//! Renders the two ntx-builder cards: local-transaction increment rate and on-chain counter
//! tracking.

use maud::{Markup, html};

use super::super::helpers::{
    copy_button,
    format_success_rate,
    format_timestamp,
    metric_row,
    truncate,
};
use crate::status::{CounterTrackingDetails, IncrementDetails};

pub(in crate::view) fn render_ntx_increment(details: &IncrementDetails, healthy: bool) -> Markup {
    let metrics_class = if healthy {
        "test-metrics healthy"
    } else {
        "test-metrics unhealthy"
    };
    html! {
        div class="service-details" {
            div class="nested-status" {
                strong { "Local Transactions:" }
                div class=(metrics_class) {
                    (metric_row(
                        "Success Rate:",
                        &format_success_rate(details.success_count, details.failure_count),
                    ))
                    @if let Some(blocks) = details.last_latency_blocks {
                        (metric_row("Latency:", &format!("{blocks} blocks")))
                    }
                    @if let Some(tx) = &details.last_tx_id {
                        div class="metric-row" {
                            span class="metric-label" { "Last TX ID:" }
                            span class="metric-value" {
                                (truncate(tx, 16)) "..."
                                (copy_button(tx, "TX ID"))
                            }
                        }
                    }
                }
            }
        }
    }
}

pub(in crate::view) fn render_ntx_tracking(
    details: &CounterTrackingDetails,
    healthy: bool,
) -> Markup {
    let metrics_class = if healthy {
        "test-metrics healthy"
    } else {
        "test-metrics unhealthy"
    };
    html! {
        div class="service-details" {
            div class="nested-status" {
                strong { "Network Transactions:" }
                div class=(metrics_class) {
                    (metric_row(
                        "Current Value:",
                        &details
                            .current_value
                            .map_or_else(|| "-".to_string(), |v| v.to_string()),
                    ))
                    @if let Some(expected) = details.expected_value {
                        (metric_row("Expected Value:", &expected.to_string()))
                    }
                    @if let Some(pending) = details.pending_increments {
                        (metric_row("Pending Notes:", &pending.to_string()))
                    }
                    @if let Some(ts) = details.last_updated {
                        (metric_row("Last Updated:", &format_timestamp(ts)))
                    }
                }
            }
        }
    }
}
