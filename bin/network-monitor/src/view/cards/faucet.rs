//! Renders the faucet card: HTTP test outcome plus the metadata block (token id, supply, decimals,
//! …) when the faucet exposed it.

use maud::{Markup, html};

use super::super::helpers::{copyable_value, format_success_rate, metric_row};
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
                            (copyable_value(&details.url, "URL"))
                        }
                    }
                    (metric_row(
                        "Success Rate:",
                        &format_success_rate(details.success_count, details.failure_count),
                    ))
                    (metric_row("Last Response Time:", &format!("{}ms", details.test_duration_ms)))
                    @if let Some(note_id) = &details.last_note_id {
                        div class="metric-row" {
                            span class="metric-label" { "Last Note ID:" }
                            span class="metric-value" {
                                (copyable_value(note_id, "note ID"))
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
                        (copyable_value(&metadata.id, "token ID"))
                    }
                }
                (metric_row(
                    "Version:",
                    if metadata.version.is_empty() { "-" } else { metadata.version.as_str() },
                ))
                (metric_row(
                    "Balance:",
                    &metadata.balance.map_or_else(|| "-".to_string(), |balance| balance.to_string()),
                ))
                (metric_row("Decimals:", &metadata.decimals.to_string()))
                (metric_row("Base Amount:", &metadata.base_amount.to_string()))
                (metric_row("PoW Difficulty:", &metadata.pow_load_difficulty.to_string()))
                @if let Some(url) = &metadata.explorer_url {
                    div class="metric-row" {
                        span class="metric-label" { "Explorer URL:" }
                        span class="metric-value" {
                            a class="value-text"
                                href=(url)
                                title=(url)
                                target="_blank"
                                rel="noopener noreferrer"
                            { (url) }
                        }
                    }
                }
            }
        }
    }
}
