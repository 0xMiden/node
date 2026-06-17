//! Renders the faucet card: HTTP test outcome plus the metadata block (token id, supply, decimals,
//! …) when the faucet exposed it.

use maud::{Markup, html};

use super::super::helpers::{copy_button, format_success_rate, metric_row, truncate};
use crate::faucet::{FaucetTestDetails, GetMetadataResponse};

pub(in crate::view) fn render_faucet_test(details: &FaucetTestDetails, healthy: bool) -> Markup {
    let metrics_class = if healthy {
        "test-metrics healthy"
    } else {
        "test-metrics unhealthy"
    };
    html! {
        div class="service-details" {
            div class="nested-status" {
                strong { "Faucet:" }
                div class=(metrics_class) {
                    div class="metric-row" {
                        span class="metric-label" { "URL:" }
                        span class="metric-value" {
                            (details.url) (copy_button(&details.url, "URL"))
                        }
                    }
                    (metric_row(
                        "Success Rate:",
                        &format_success_rate(details.success_count, details.failure_count),
                    ))
                    (metric_row("Last Response Time:", &format!("{}ms", details.test_duration_ms)))
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
            @if let Some(metadata) = &details.faucet_metadata {
                (render_faucet_metadata(metadata, healthy))
            }
        }
    }
}

fn render_faucet_metadata(metadata: &GetMetadataResponse, healthy: bool) -> Markup {
    let metrics_class = if healthy {
        "test-metrics healthy"
    } else {
        "test-metrics unhealthy"
    };
    html! {
        div class="nested-status" {
            strong { "Faucet Token Info:" }
            div class=(metrics_class) {
                div class="metric-row" {
                    span class="metric-label" { "Token ID:" }
                    span class="metric-value" {
                        (truncate(&metadata.id, 16)) "..."
                        (copy_button(&metadata.id, "token ID"))
                    }
                }
                (metric_row(
                    "Version:",
                    if metadata.version.is_empty() { "-" } else { metadata.version.as_str() },
                ))
                (metric_row("Max Supply:", &metadata.max_supply.to_string()))
                (metric_row("Decimals:", &metadata.decimals.to_string()))
                (metric_row("Base Amount:", &metadata.base_amount.to_string()))
                (metric_row("PoW Difficulty:", &metadata.pow_load_difficulty.to_string()))
                @if let Some(url) = &metadata.explorer_url {
                    div class="metric-row" {
                        span class="metric-label" { "Explorer URL:" }
                        span class="metric-value" {
                            a href=(url) target="_blank" rel="noopener noreferrer" { (url) }
                        }
                    }
                }
                @if let Some(url) = &metadata.note_transport_url {
                    div class="metric-row" {
                        span class="metric-label" { "Note Transport URL:" }
                        span class="metric-value" {
                            a href=(url) target="_blank" rel="noopener noreferrer" { (url) }
                        }
                    }
                }
            }
        }
    }
}
