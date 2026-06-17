//! Renders the validator card.

use maud::{Markup, html};

use super::super::helpers::{copy_button, metric_row, num_or_dash};
use crate::status::ValidatorStatusDetails;

pub(in crate::view) fn render_validator(details: &ValidatorStatusDetails, healthy: bool) -> Markup {
    let metrics_class = if healthy {
        "test-metrics healthy"
    } else {
        "test-metrics unhealthy"
    };
    html! {
        div class="service-details" {
            div class="nested-status" {
                strong { "Validator:" }
                div class=(metrics_class) {
                    div class="metric-row" {
                        span class="metric-label" { "URL:" }
                        span class="metric-value" {
                            (details.url) (copy_button(&details.url, "URL"))
                        }
                    }
                    (metric_row("Version:", &details.version))
                    (metric_row("Chain Tip:", &num_or_dash(u64::from(details.chain_tip), healthy)))
                    (metric_row(
                        "Validated Transactions:",
                        &num_or_dash(details.validated_transactions_count, healthy),
                    ))
                    (metric_row(
                        "Signed Blocks:",
                        &num_or_dash(details.signed_blocks_count, healthy),
                    ))
                }
            }
        }
    }
}
