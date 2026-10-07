//! Renders funding account status and native asset metadata.

use maud::{Markup, html};

use super::super::helpers::{copyable_value, metric_row, token_amount};
use crate::status::FundingStatusDetails;

pub(in crate::view) fn render_funding_service(
    details: &FundingStatusDetails,
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
                strong { "Funding Service:" }
                div class=(metrics_class) {
                    div class="metric-row" {
                        span class="metric-label" { "URL:" }
                        span class="metric-value" { (copyable_value(&details.url, "URL")) }
                    }
                    @if let Some(status) = &details.status {
                        @let decimals = status.native_asset.decimals;
                        @let symbol = &status.native_asset.symbol;
                        (metric_row("Version:", &status.version))
                        div class="metric-row" {
                            span class="metric-label" { "Account ID:" }
                            span class="metric-value" { (copyable_value(&status.account_id, "Account ID")) }
                        }
                        (metric_row("Chain Tip:", &status.chain_tip.to_string()))
                        (metric_row("Balance:", &token_amount(status.balance, decimals, symbol)))
                        (metric_row("Max Request:", &token_amount(status.max_amount, decimals, symbol)))
                        (metric_row("Verification Base Fee:", &token_amount(u64::from(status.verification_base_fee), decimals, symbol)))
                    }
                }
            }
            @if let Some(status) = &details.status {
                div class="nested-status" {
                    strong { "Native Asset:" }
                    div class=(metrics_class) {
                        (metric_row("Name:", &status.native_asset.name))
                        (metric_row("Symbol:", &status.native_asset.symbol))
                        (metric_row("Decimals:", &status.native_asset.decimals.to_string()))
                        div class="metric-row" {
                            span class="metric-label" { "Asset ID:" }
                            span class="metric-value" { (copyable_value(&status.native_asset.asset_id, "Asset ID")) }
                        }
                    }
                }
            }
        }
    }
}
