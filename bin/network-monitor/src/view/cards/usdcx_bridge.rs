//! Renders the `USDCx` bridge card: the Miden faucet supply and pause state, the xReserve
//! collateral and pause flags, and the bridge activity of the last 24 hours.

use maud::{Markup, html};

use super::super::helpers::{copyable_value, format_timestamp, metric_row, token_amount};
use crate::status::{
    UsdcxActivityDetails,
    UsdcxBridgeDetails,
    UsdcxBridgeEventKind,
    UsdcxFaucetDetails,
    XReserveDetails,
};

pub(in crate::view) fn render_usdcx_bridge(details: &UsdcxBridgeDetails) -> Markup {
    html! {
        div class="service-details" {
            (render_faucet(details.faucet.as_ref()))
            (render_xreserve(details))
            (render_activity(details.activity.as_ref()))
        }
        @if let Some(error) = &details.activity_error {
            div class="warning-banner" {
                div class="metric-row" {
                    span class="metric-label" { "Bridge activity" }
                }
                div class="warning-text" { (error) }
            }
        }
    }
}

fn render_faucet(faucet: Option<&UsdcxFaucetDetails>) -> Markup {
    let healthy = faucet.is_some_and(|faucet| !faucet.paused);
    html! {
        div class="nested-status" {
            strong { "Miden Faucet:" }
            div class=(metrics_class(healthy)) {
                @if let Some(faucet) = faucet {
                    div class="metric-row" {
                        span class="metric-label" { "Faucet ID:" }
                        span class="metric-value" {
                            (copyable_value(&faucet.faucet_id, "faucet ID"))
                        }
                    }
                    (metric_row(
                        "Circulating Supply:",
                        &token_amount(faucet.circulating_supply, faucet.decimals, &faucet.symbol),
                    ))
                    (metric_row("Mint and Burn:", if faucet.paused { "Paused" } else { "Active" }))
                    (metric_row("Circle Domain:", &faucet.circle_domain.to_string()))
                    (metric_row("Block:", &faucet.block_num.to_string()))
                } @else {
                    (metric_row("Circulating Supply:", "-"))
                    (metric_row("Mint and Burn:", "-"))
                }
            }
        }
    }
}

fn render_xreserve(details: &UsdcxBridgeDetails) -> Markup {
    let xreserve = details.xreserve.as_ref();
    let coverage = xreserve.zip(details.faucet.as_ref()).and_then(|(xreserve, faucet)| {
        (xreserve.collateral_decimals == faucet.decimals).then(|| coverage(xreserve, faucet))
    });
    let healthy = xreserve.is_some_and(|xreserve| {
        !xreserve.paused && !xreserve.deposits_paused && !xreserve.withdrawals_paused
    }) && coverage.as_ref().is_none_or(|(covered, _)| *covered);
    html! {
        div class="nested-status" {
            strong { "xReserve:" }
            div class=(metrics_class(healthy)) {
                div class="metric-row" {
                    span class="metric-label" { "Contract:" }
                    span class="metric-value" {
                        (copyable_value(&details.xreserve_address, "contract address"))
                    }
                }
                @if let Some(xreserve) = xreserve {
                    (metric_row("Chain ID:", &xreserve.chain_id.to_string()))
                    (metric_row(
                        "Collateral:",
                        &token_amount(xreserve.collateral, xreserve.collateral_decimals, "USDC"),
                    ))
                    @if let Some((_, difference)) = &coverage {
                        (metric_row("Collateral − Supply:", difference))
                    }
                    (metric_row("Contract State:", paused_label(xreserve.paused, "Active")))
                    (metric_row("Deposits:", paused_label(xreserve.deposits_paused, "Enabled")))
                    (metric_row(
                        "Withdrawals:",
                        paused_label(xreserve.withdrawals_paused, "Enabled"),
                    ))
                } @else {
                    (metric_row("Collateral:", "-"))
                    (metric_row("Deposits:", "-"))
                    (metric_row("Withdrawals:", "-"))
                }
            }
        }
    }
}

fn render_activity(activity: Option<&UsdcxActivityDetails>) -> Markup {
    html! {
        div class="nested-status" {
            strong { "Last 24 Hours:" }
            div class="test-metrics healthy" {
                @if let Some(activity) = activity {
                    (metric_row("Deposits:", &activity.deposits_24h.to_string()))
                    (metric_row("Withdrawals:", &activity.withdrawals_24h.to_string()))
                    @if let Some(latest) = &activity.latest {
                        (metric_row(
                            "Latest Event:",
                            &format!(
                                "{} at {} (block {})",
                                event_label(latest.kind),
                                format_timestamp(latest.timestamp),
                                latest.block_num,
                            ),
                        ))
                    } @else {
                        (metric_row("Latest Event:", "-"))
                    }
                    @if activity.synced_to < activity.chain_tip {
                        (metric_row(
                            "Catching Up:",
                            &format!(
                                "synced to block {} of {}",
                                activity.synced_to,
                                activity.chain_tip,
                            ),
                        ))
                    }
                } @else {
                    (metric_row("Deposits:", "-"))
                    (metric_row("Withdrawals:", "-"))
                }
            }
        }
    }
}

/// Returns whether the collateral covers the supply, and the difference between them in tokens.
///
/// Both amounts must use the same decimals.
fn coverage(xreserve: &XReserveDetails, faucet: &UsdcxFaucetDetails) -> (bool, String) {
    let decimals = xreserve.collateral_decimals;
    if let Some(surplus) = xreserve.collateral.checked_sub(faucet.circulating_supply) {
        (true, token_amount(surplus, decimals, "USDC"))
    } else {
        let deficit = faucet.circulating_supply - xreserve.collateral;
        (false, format!("-{} (deficit)", token_amount(deficit, decimals, "USDC")))
    }
}

fn metrics_class(healthy: bool) -> &'static str {
    if healthy {
        "test-metrics healthy"
    } else {
        "test-metrics unhealthy"
    }
}

fn paused_label(paused: bool, unpaused: &'static str) -> &'static str {
    if paused { "Paused" } else { unpaused }
}

fn event_label(kind: UsdcxBridgeEventKind) -> &'static str {
    match kind {
        UsdcxBridgeEventKind::Deposit => "Deposit",
        UsdcxBridgeEventKind::Withdrawal => "Withdrawal",
    }
}
