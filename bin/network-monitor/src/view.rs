//! Server-side HTML rendering for the network monitor dashboard.
//!
//! [`page`] returns the full HTML document; [`status_fragment`] returns just the cards grid that
//! htmx swaps into `#status-container` on each poll.

use maud::{DOCTYPE, Markup, PreEscaped, html};
use time::OffsetDateTime;
use time::macros::format_description;

use crate::faucet::{FaucetTestDetails, GetMetadataResponse};
use crate::frontend::ServerState;
use crate::remote_prover::ProofType;
use crate::status::{
    CounterTrackingDetails,
    ExplorerStatusDetails,
    IncrementDetails,
    NetworkStatus,
    NoteTransportStatusDetails,
    ProverTestOutcome,
    RemoteProverDetails,
    RpcStatusDetails,
    ServiceDetails,
    ServiceStatus,
    Status,
    ValidatorStatusDetails,
    WorkerStatusDetails,
    current_unix_timestamp_secs,
};

/// Maximum allowed block delta between the explorer's tip and the RPC's tip before we surface a
/// warning banner on the explorer card. ~1 minute at current block cadence.
const EXPLORER_LAG_TOLERANCE: u64 = 20;

const COPY_ICON_SVG: &str = r#"<svg class="copy-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>"#;

// PUBLIC ENTRYPOINTS
// ================================================================================================

/// Full dashboard page. The `#status-container` is pre-filled with the initial card grid so the
/// page renders without a flash of empty content while htmx fires its first poll.
pub fn page(state: &ServerState) -> Markup {
    let snapshot = snapshot(state);
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="UTF-8";
                meta name="viewport" content="width=device-width, initial-scale=1.0";
                title { "Miden Network Monitor" }
                link rel="stylesheet" href="/assets/index.css";
                link rel="icon" href="/assets/favicon.ico" type="image/x-icon";
                script src="/assets/htmx.min.js" {}
                script src="/assets/probes.js" defer {}
            }
            body {
                div class="container" {
                    div class="header" {
                        div class="logo" {
                            div class="logo-icon" {}
                            div class="logo-text" {
                                "Miden "
                                span class="highlight" { (snapshot.network_name) }
                            }
                        }
                    }
                    div class="main-content" {
                        div class="form-title" { "Network Status Dashboard" }
                        div id="status-container"
                            hx-get="/fragments/status"
                            hx-trigger="every 10s"
                            hx-swap="innerHTML"
                        {
                            (status_fragment(&snapshot))
                        }
                    }
                }
                (footer(&snapshot))
            }
        }
    }
}

/// Card grid + last-updated line. Returned from `/fragments/status` for htmx to swap into
/// `#status-container`.
pub fn status_fragment(snapshot: &NetworkStatus) -> Markup {
    let rpc_chain_tip = find_rpc_chain_tip(&snapshot.services);
    html! {
        @for service in &snapshot.services {
            (service_card(service, rpc_chain_tip))
        }
        div class="refresh-button-container" {
            button class="button"
                hx-get="/fragments/status"
                hx-target="#status-container"
                hx-swap="innerHTML"
            {
                svg class="button-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" {
                    path d="M23 4v6h-6M1 20v-6h6M20.49 9A9 9 0 0 0 5.64 5.64L1 10m22 4l-4.64 4.36A9 9 0 0 1 3.51 15" {}
                }
                " Refresh Status"
            }
        }
        div class="note" {
            "Last updated: " (format_timestamp(snapshot.last_updated))
        }
    }
}

// SNAPSHOT HELPER
// ================================================================================================

/// Snapshots every service receiver into a single `NetworkStatus` value. Same shape that
/// [`crate::frontend::get_status`] serialises to JSON.
pub fn snapshot(state: &ServerState) -> NetworkStatus {
    let services: Vec<ServiceStatus> =
        state.services.iter().map(|rx| rx.borrow().clone()).collect();
    NetworkStatus {
        services,
        last_updated: current_unix_timestamp_secs(),
        monitor_version: state.monitor_version.clone(),
        network_name: state.network_name.clone(),
    }
}

// FOOTER
// ================================================================================================

fn footer(snapshot: &NetworkStatus) -> Markup {
    let total = snapshot.services.len();
    let healthy = snapshot.services.iter().filter(|s| s.status == Status::Healthy).count();
    let all_healthy = total > 0 && healthy == total;
    let overall = if all_healthy {
        "All Systems Operational".to_string()
    } else {
        format!("{healthy}/{total} Services Healthy")
    };
    let overall_class = if all_healthy {
        "footer-value healthy"
    } else {
        "footer-value unhealthy"
    };

    html! {
        div class="footer" {
            div class="footer-content" {
                div class="footer-section" {
                    div class="footer-label" { "Network Status" }
                    div class=(overall_class) { (overall) }
                }
                div class="footer-section footer-center" {
                    div class="footer-value" {
                        @if !snapshot.monitor_version.is_empty() {
                            "Monitor v" (snapshot.monitor_version)
                        }
                    }
                }
                div class="footer-section tokens-section" {
                    div class="footer-label" { "Services" }
                    div class="footer-value" { (total) " Services" }
                }
            }
            div class="footer-line" {}
        }
    }
}

// CARDS
// ================================================================================================

fn service_card(service: &ServiceStatus, rpc_chain_tip: Option<u32>) -> Markup {
    let healthy = matches!(service.status, Status::Healthy);
    let card_class = if healthy {
        "service-card healthy"
    } else {
        "service-card unhealthy"
    };
    let (status_icon, status_text) = match service.status {
        Status::Healthy => ("✓", "HEALTHY"),
        Status::Unhealthy => ("✗", "UNHEALTHY"),
        Status::Unknown => ("?", "UNKNOWN"),
    };

    html! {
        div class=(card_class) {
            div class="service-header" {
                div class="service-name" { (service.name) }
                div class={"service-status " (status_text.to_lowercase())} {
                    (status_icon) " " (status_text)
                }
            }
            div class="service-content" {
                (render_details(service, rpc_chain_tip))
                @if let Some(err) = &service.error {
                    div class="error-message" { (err) }
                }
            }
            div class="service-timestamp" {
                "Last checked: " (format_timestamp(service.last_checked))
            }
        }
    }
}

fn render_details(service: &ServiceStatus, rpc_chain_tip: Option<u32>) -> Markup {
    let healthy = matches!(service.status, Status::Healthy);
    match &service.details {
        ServiceDetails::RpcStatus(d) => render_rpc_status(d),
        ServiceDetails::RemoteProverStatus(d) => render_remote_prover(d),
        ServiceDetails::FaucetTest(d) => render_faucet_test(d, healthy),
        ServiceDetails::NtxIncrement(d) => render_ntx_increment(d, healthy),
        ServiceDetails::NtxTracking(d) => render_ntx_tracking(d, healthy),
        ServiceDetails::ExplorerStatus(d) => render_explorer(d, rpc_chain_tip, healthy),
        ServiceDetails::NoteTransportStatus(d) => render_note_transport(d, healthy),
        ServiceDetails::ValidatorStatus(d) => render_validator(d, healthy),
        ServiceDetails::Error => html! {},
    }
}

// RPC STATUS
// ================================================================================================

fn render_rpc_status(details: &RpcStatusDetails) -> Markup {
    html! {
        div class="service-details" data-grpc-url=(details.url) data-grpc-path="/rpc.Api/Status" {
            div class="detail-item" {
                strong { "URL: " }
                (details.url)
                (copy_button(&details.url, "URL"))
            }
            div class="detail-item" {
                strong { "Version: " }
                (details.version)
            }
            @if let Some(genesis) = &details.genesis_commitment {
                div class="detail-item" {
                    strong { "Genesis: " }
                    span class="genesis-value" {
                        "0x" (truncate(genesis, 20)) "..."
                    }
                    (copy_button(genesis, "genesis commitment"))
                }
            }
            (probe_section_placeholder())
            @if let Some(store) = &details.store_status {
                div class="nested-status" {
                    div class="detail-item" { strong { "Store" } }
                    (metric_row("Version:", &store.version))
                    (metric_row("Status:", &format!("{:?}", store.status)))
                    (metric_row("Chain Tip:", &store.chain_tip.to_string()))
                }
            }
            @if let Some(block_producer) = &details.block_producer_status {
                @let mempool = &block_producer.mempool;
                div class="nested-status" {
                    div class="detail-item" { strong { "Block Producer" } }
                    (metric_row("Version:", &block_producer.version))
                    (metric_row("Status:", &format!("{:?}", block_producer.status)))
                    (metric_row("Chain Tip:", &block_producer.chain_tip.to_string()))
                    div class="nested-status mempool-stats" {
                        strong { "Mempool stats:" }
                        (metric_row("Unbatched TXs:", &mempool.unbatched_transactions.to_string()))
                        (metric_row("Proposed Batches:", &mempool.proposed_batches.to_string()))
                        (metric_row("Proven Batches:", &mempool.proven_batches.to_string()))
                    }
                }
            }
        }
    }
}

// REMOTE PROVER
// ================================================================================================

fn render_remote_prover(details: &RemoteProverDetails) -> Markup {
    let proxy = &details.status;
    html! {
        div class="service-details"
            data-grpc-url=(proxy.url)
            data-grpc-path="/remote_prover.ProxyStatusApi/Status"
        {
            div class="detail-item" {
                strong { "URL: " }
                (proxy.url)
                (copy_button(&proxy.url, "URL"))
            }
            div class="detail-item" {
                strong { "Version: " }
                (proxy.version)
            }
            div class="detail-item" {
                strong { "Proof Type: " }
                (proof_type_label(&proxy.supported_proof_type))
            }
            (probe_section_placeholder())
            @if !proxy.workers.is_empty() {
                (render_workers(&proxy.workers))
            }
            @if let Some(test) = &details.test {
                (render_prover_test(test))
            }
        }
    }
}

fn render_workers(workers: &[WorkerStatusDetails]) -> Markup {
    html! {
        div class="nested-status" {
            strong { "Workers (" (workers.len()) "):" }
            @for worker in workers {
                @let badge_class = match worker.status {
                    Status::Healthy => "worker-status-badge healthy",
                    Status::Unhealthy => "worker-status-badge unhealthy",
                    Status::Unknown => "worker-status-badge unknown",
                };
                div class="worker-status" {
                    span class="worker-name" {
                        @if worker.name.len() > 20 {
                            (truncate(&worker.name, 20)) "..."
                            (copy_button(&worker.name, "worker name"))
                        } @else {
                            (worker.name)
                        }
                    }
                    span class="worker-version" { (worker.version) }
                    span class=(badge_class) { (status_label(&worker.status)) }
                }
            }
        }
    }
}

fn render_prover_test(test: &ProverTestOutcome) -> Markup {
    let metrics_class = if matches!(test.status, Status::Healthy) {
        "test-metrics healthy"
    } else {
        "test-metrics unhealthy"
    };
    #[expect(clippy::cast_precision_loss, reason = "display only")]
    let kb = test.details.proof_size_bytes as f64 / 1024.0;
    html! {
        div class="nested-status" {
            strong {
                "Proof Generation Testing (" (proof_type_label(&test.details.proof_type)) "):"
            }
            div class=(metrics_class) {
                (metric_row(
                    "Success Rate:",
                    &format_success_rate(test.details.success_count, test.details.failure_count),
                ))
                (metric_row("Last Response Time:", &format!("{}ms", test.details.test_duration_ms)))
                (metric_row("Last Proof Size:", &format!("{kb:.2} KB")))
            }
        }
    }
}

// FAUCET
// ================================================================================================

fn render_faucet_test(details: &FaucetTestDetails, healthy: bool) -> Markup {
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
            }
        }
    }
}

// NTX INCREMENT
// ================================================================================================

fn render_ntx_increment(details: &IncrementDetails, healthy: bool) -> Markup {
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

// NTX TRACKING
// ================================================================================================

fn render_ntx_tracking(details: &CounterTrackingDetails, healthy: bool) -> Markup {
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

// EXPLORER
// ================================================================================================

fn render_explorer(
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

// NOTE TRANSPORT
// ================================================================================================

fn render_note_transport(details: &NoteTransportStatusDetails, healthy: bool) -> Markup {
    let metrics_class = if healthy {
        "test-metrics healthy"
    } else {
        "test-metrics unhealthy"
    };
    html! {
        div class="service-details" {
            div class="nested-status" {
                strong { "Note Transport:" }
                div class=(metrics_class) {
                    div class="metric-row" {
                        span class="metric-label" { "URL:" }
                        span class="metric-value" {
                            (details.url) (copy_button(&details.url, "URL"))
                        }
                    }
                    (metric_row("Serving Status:", &details.serving_status))
                }
            }
        }
    }
}

// VALIDATOR
// ================================================================================================

fn render_validator(details: &ValidatorStatusDetails, healthy: bool) -> Markup {
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

// SHARED HELPERS
// ================================================================================================

fn metric_row(label: &str, value: &str) -> Markup {
    html! {
        div class="metric-row" {
            span class="metric-label" { (label) }
            span class="metric-value" { (value) }
        }
    }
}

fn copy_button(value: &str, label: &str) -> Markup {
    let onclick = format!("copyToClipboard({}, event)", json_string(value));
    html! {
        button class="copy-button" onclick=(onclick) title={"Copy full " (label)} {
            (PreEscaped(COPY_ICON_SVG))
        }
    }
}

/// Placeholder div that `probes.js` populates with the live gRPC-Web probe result. Using a
/// placeholder keeps the maud templates free of JS-rendered content while preserving the visual
/// slot in the card.
fn probe_section_placeholder() -> Markup {
    html! {
        div class="probe-section" {
            div class="probe-result probe-pending" {
                span class="probe-spinner" {}
                span class="probe-status-badge" { "gRPC-Web: Checking..." }
            }
        }
    }
}

/// Returns a prefix of `value` no longer than `max_len` bytes, snapping back to the nearest UTF-8
/// char boundary so this never panics on multi-byte input. Callers in this module currently pass
/// hex strings or ASCII names, but the boundary check keeps the helper safe to reuse.
fn truncate(value: &str, max_len: usize) -> &str {
    if value.len() <= max_len {
        return value;
    }
    let mut end = max_len;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

fn num_or_dash(value: u64, healthy: bool) -> String {
    if healthy { value.to_string() } else { "-".to_string() }
}

fn commitment_or_dash(value: &str, label: &str, healthy: bool) -> Markup {
    if healthy && !value.is_empty() {
        html! {
            (truncate(value, 20)) "..." (copy_button(value, label))
        }
    } else {
        html! { "-" }
    }
}

fn format_success_rate(success: u64, failure: u64) -> String {
    let total = success + failure;
    if total == 0 {
        return "N/A".to_string();
    }
    #[expect(clippy::cast_precision_loss, reason = "display only")]
    let pct = (success as f64 / total as f64) * 100.0;
    format!("{pct:.1}%")
}

fn proof_type_label(proof_type: &ProofType) -> &'static str {
    match proof_type {
        ProofType::Transaction => "Transaction",
        ProofType::Block => "Block",
        ProofType::Batch => "Batch",
    }
}

fn status_label(status: &Status) -> &'static str {
    match status {
        Status::Healthy => "Healthy",
        Status::Unhealthy => "Unhealthy",
        Status::Unknown => "Unknown",
    }
}

fn json_string(value: &str) -> String {
    serde_json::to_string(value).expect("string serialisation is infallible")
}

fn format_timestamp(secs: u64) -> String {
    if secs == 0 {
        return "-".to_string();
    }
    let Ok(unix) = i64::try_from(secs) else {
        return "-".to_string();
    };
    let Ok(dt) = OffsetDateTime::from_unix_timestamp(unix) else {
        return "-".to_string();
    };
    let fmt = format_description!("[year]-[month]-[day] [hour]:[minute]:[second] UTC");
    dt.format(&fmt).unwrap_or_else(|_| "-".to_string())
}

fn find_rpc_chain_tip(services: &[ServiceStatus]) -> Option<u32> {
    for service in services {
        if let ServiceDetails::RpcStatus(rpc) = &service.details {
            if let Some(store) = &rpc.store_status {
                return Some(store.chain_tip);
            }
            if let Some(bp) = &rpc.block_producer_status {
                return Some(bp.chain_tip);
            }
        }
    }
    None
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote_prover::{ProofType, ProverTestDetails};
    use crate::status::{
        BlockProducerStatusDetails,
        MempoolStatusDetails,
        RemoteProverStatusDetails,
        StoreStatusDetails,
    };

    // truncate
    // ----------------------------------------------------------------------------------------

    #[test]
    fn truncate_short_string_is_returned_verbatim() {
        assert_eq!(truncate("abc", 10), "abc");
    }

    #[test]
    fn truncate_at_boundary_takes_prefix() {
        assert_eq!(truncate("abcdef", 3), "abc");
    }

    #[test]
    fn truncate_snaps_back_to_char_boundary() {
        // 'é' is 2 bytes (0xC3 0xA9). Asking for 4 bytes lands inside the second 'é'.
        let value = "abéé";
        let out = truncate(value, 4);
        assert_eq!(out, "abé");
        assert!(value.is_char_boundary(out.len()));
    }

    // format_timestamp
    // ----------------------------------------------------------------------------------------

    #[test]
    fn format_timestamp_zero_renders_dash() {
        assert_eq!(format_timestamp(0), "-");
    }

    #[test]
    fn format_timestamp_renders_utc() {
        // 2021-01-01T00:00:00Z
        assert_eq!(format_timestamp(1_609_459_200), "2021-01-01 00:00:00 UTC");
    }

    #[test]
    fn format_timestamp_unrepresentable_renders_dash() {
        assert_eq!(format_timestamp(u64::MAX), "-");
    }

    // status_fragment — one card per ServiceDetails variant
    // ----------------------------------------------------------------------------------------

    fn snapshot_with(services: Vec<ServiceStatus>) -> NetworkStatus {
        NetworkStatus {
            services,
            last_updated: 1_609_459_200,
            monitor_version: "0.0.0".to_string(),
            network_name: "Test".to_string(),
        }
    }

    fn healthy(name: &str, details: ServiceDetails) -> ServiceStatus {
        ServiceStatus {
            name: name.to_string(),
            status: Status::Healthy,
            last_checked: 1_609_459_200,
            error: None,
            details,
        }
    }

    fn rpc_details() -> RpcStatusDetails {
        RpcStatusDetails {
            url: "https://rpc.example".to_string(),
            version: "1.2.3".to_string(),
            genesis_commitment: Some("0xabcdef".to_string()),
            store_status: Some(StoreStatusDetails {
                version: "1.2.3".to_string(),
                status: Status::Healthy,
                chain_tip: 42,
            }),
            block_producer_status: Some(BlockProducerStatusDetails {
                version: "1.2.3".to_string(),
                status: Status::Healthy,
                chain_tip: 42,
                mempool: MempoolStatusDetails {
                    unbatched_transactions: 1,
                    proposed_batches: 2,
                    proven_batches: 3,
                },
            }),
        }
    }

    fn render(services: Vec<ServiceStatus>) -> String {
        status_fragment(&snapshot_with(services)).into_string()
    }

    #[test]
    fn renders_rpc_status_card() {
        let html = render(vec![healthy("rpc", ServiceDetails::RpcStatus(rpc_details()))]);
        assert!(html.contains("rpc"));
        assert!(html.contains("Mempool stats"));
        assert!(html.contains("Chain Tip"));
    }

    #[test]
    fn renders_remote_prover_card() {
        let details = RemoteProverDetails {
            status: RemoteProverStatusDetails {
                url: "https://prover.example".to_string(),
                version: "1.0".to_string(),
                supported_proof_type: ProofType::Transaction,
                workers: vec![WorkerStatusDetails {
                    name: "worker-1".to_string(),
                    version: "1.0".to_string(),
                    status: Status::Healthy,
                }],
            },
            test: Some(ProverTestOutcome {
                details: ProverTestDetails {
                    test_duration_ms: 50,
                    proof_size_bytes: 2048,
                    success_count: 9,
                    failure_count: 1,
                    proof_type: ProofType::Transaction,
                },
                status: Status::Healthy,
                error: None,
            }),
        };
        let html = render(vec![healthy("prover", ServiceDetails::RemoteProverStatus(details))]);
        assert!(html.contains("Workers"));
        assert!(html.contains("worker-1"));
        assert!(html.contains("Proof Generation Testing"));
    }

    #[test]
    fn renders_faucet_card() {
        let details = FaucetTestDetails {
            url: "https://faucet.example".to_string(),
            test_duration_ms: 12,
            success_count: 1,
            failure_count: 0,
            last_tx_id: Some("deadbeef".to_string()),
            faucet_metadata: Some(GetMetadataResponse {
                version: "1.0".to_string(),
                id: "tokenid".to_string(),
                max_supply: 1_000_000,
                decimals: 8,
                explorer_url: Some("https://explorer.example".to_string()),
                pow_load_difficulty: 4,
                base_amount: 100,
            }),
        };
        let html = render(vec![healthy("faucet", ServiceDetails::FaucetTest(details))]);
        assert!(html.contains("Faucet:"));
        assert!(html.contains("Faucet Token Info"));
        assert!(html.contains("Last TX ID"));
    }

    #[test]
    fn renders_ntx_increment_card() {
        let details = IncrementDetails {
            success_count: 5,
            failure_count: 0,
            last_tx_id: Some("abc123".to_string()),
            last_latency_blocks: Some(2),
        };
        let html = render(vec![healthy("ntx-inc", ServiceDetails::NtxIncrement(details))]);
        assert!(html.contains("Local Transactions"));
        assert!(html.contains("Latency"));
    }

    #[test]
    fn renders_ntx_tracking_card() {
        let details = CounterTrackingDetails {
            current_value: Some(7),
            expected_value: Some(8),
            last_updated: Some(1_609_459_200),
            pending_increments: Some(1),
        };
        let html = render(vec![healthy("ntx-track", ServiceDetails::NtxTracking(details))]);
        assert!(html.contains("Network Transactions"));
        assert!(html.contains("Pending Notes"));
    }

    #[test]
    fn renders_explorer_card() {
        let details = ExplorerStatusDetails {
            block_number: 100,
            timestamp: 1_609_459_200,
            number_of_transactions: 1,
            number_of_nullifiers: 1,
            number_of_notes: 1,
            number_of_account_updates: 1,
            block_commitment: "0x".repeat(20),
            chain_commitment: "0x".repeat(20),
            proof_commitment: "0x".repeat(20),
        };
        let html = render(vec![healthy("explorer", ServiceDetails::ExplorerStatus(details))]);
        assert!(html.contains("Explorer:"));
        assert!(html.contains("Block Height"));
    }

    #[test]
    fn renders_note_transport_card() {
        let details = NoteTransportStatusDetails {
            url: "https://nt.example".to_string(),
            serving_status: "SERVING".to_string(),
        };
        let html =
            render(vec![healthy("note-transport", ServiceDetails::NoteTransportStatus(details))]);
        assert!(html.contains("Note Transport"));
        assert!(html.contains("SERVING"));
    }

    #[test]
    fn renders_validator_card() {
        let details = ValidatorStatusDetails {
            url: "https://validator.example".to_string(),
            version: "1.0".to_string(),
            chain_tip: 42,
            validated_transactions_count: 10,
            signed_blocks_count: 5,
        };
        let html = render(vec![healthy("validator", ServiceDetails::ValidatorStatus(details))]);
        assert!(html.contains("Validator:"));
        assert!(html.contains("Signed Blocks"));
    }

    #[test]
    fn renders_error_variant_without_panicking() {
        let html = render(vec![ServiceStatus {
            name: "broken".to_string(),
            status: Status::Unhealthy,
            last_checked: 1_609_459_200,
            error: Some("boom".to_string()),
            details: ServiceDetails::Error,
        }]);
        assert!(html.contains("broken"));
        assert!(html.contains("UNHEALTHY"));
        assert!(html.contains("boom"));
    }

    #[test]
    fn fragment_includes_refresh_button_and_last_updated() {
        let html = render(vec![healthy("rpc", ServiceDetails::RpcStatus(rpc_details()))]);
        assert!(html.contains("Refresh Status"));
        assert!(html.contains("Last updated"));
    }

    #[test]
    fn explorer_lag_warning_appears_when_delta_exceeds_tolerance() {
        // RPC chain tip is 42 (see `rpc_details`); explorer at 0 puts it 42 blocks behind, well
        // past `EXPLORER_LAG_TOLERANCE`.
        let explorer = ExplorerStatusDetails::default();
        let html = render(vec![
            healthy("rpc", ServiceDetails::RpcStatus(rpc_details())),
            healthy("explorer", ServiceDetails::ExplorerStatus(explorer)),
        ]);
        assert!(html.contains("Explorer tip is"));
        assert!(html.contains("behind"));
    }
}
