//! Server-side HTML rendering for the network monitor dashboard.
//!
//! [`page`] renders the full dashboard. [`status_fragment`] refreshes the dashboard and footer
//! from the same snapshot on each poll.

mod cards;
mod helpers;

use helpers::{HealthCounts, format_timestamp, status_class, status_label};
use maud::{DOCTYPE, Markup, PreEscaped, html};

use crate::frontend::ServerState;
use crate::status::{
    NetworkStatus,
    ServiceDetails,
    ServiceStatus,
    Status,
    current_unix_timestamp_secs,
};

/// Applies the saved theme before the first paint, so a dark page does not flash light on load.
const THEME_INIT_JS: &str = r#"try{if(localStorage.getItem("theme")==="dark")document.documentElement.dataset.theme="dark"}catch(e){}"#;

const NETWORK_ICON_SVG: &str = r#"<svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="6.2" stroke="currentColor" fill="none" stroke-width="1.4"/><path d="M1.8 8h12.4M8 1.8c1.8 1.9 2.6 4 2.6 6.2S9.8 12.3 8 14.2M8 1.8C6.2 3.7 5.4 5.8 5.4 8s.8 4.3 2.6 6.2" stroke="currentColor" fill="none" stroke-width="1.2"/></svg>"#;

const THEME_ICON_SVG: &str = r#"<svg width="18" height="18" viewBox="0 0 18 18" aria-hidden="true"><circle cx="9" cy="9" r="7" stroke="currentColor" stroke-width="1.6" fill="none"/><path d="M9 2a7 7 0 0 1 0 14z" fill="currentColor"/></svg>"#;

// PUBLIC ENTRYPOINTS
// ================================================================================================

/// Full dashboard page. The `#status-container` is pre-filled with the initial status fragment so
/// the page renders without a flash of empty content while htmx fires its first poll.
pub fn page(state: &ServerState) -> Markup {
    let snapshot = snapshot(state);
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="UTF-8";
                meta name="viewport" content="width=device-width, initial-scale=1.0";
                title { "Miden Network Monitor" }
                link rel="preconnect" href="https://fonts.googleapis.com";
                link rel="stylesheet"
                    href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap";
                link rel="stylesheet" href="/assets/index.css";
                link rel="icon" href="/assets/favicon.ico" type="image/x-icon";
                script { (PreEscaped(THEME_INIT_JS)) }
                script src="/assets/htmx.min.js" {}
                script src="/assets/probes.js" defer {}
            }
            body {
                header class="header" {
                    div class="logo" {
                        img src="/assets/logo.png" alt="Miden" width="123" height="38";
                    }
                    div class="header-actions" {
                        div class="network-pill" {
                            (PreEscaped(NETWORK_ICON_SVG))
                            (snapshot.network_name)
                        }
                        @if !snapshot.monitor_version.is_empty() {
                            div class="version-chip" { "Monitor v" (snapshot.monitor_version) }
                        }
                        button class="theme-toggle" id="theme-toggle" type="button"
                            aria-label="Toggle dark theme"
                        {
                            (PreEscaped(THEME_ICON_SVG))
                        }
                    }
                }
                div id="status-container"
                    hx-get="/fragments/status"
                    hx-trigger="every 10s"
                    hx-swap="innerHTML"
                {
                    (status_fragment(&snapshot))
                }
            }
        }
    }
}

/// Renders all dashboard content that depends on the current snapshot.
pub fn status_fragment(snapshot: &NetworkStatus) -> Markup {
    let rpc_chain_tip = find_rpc_chain_tip(&snapshot.services);
    let validators: Vec<_> = snapshot
        .services
        .iter()
        .filter_map(|service| {
            if let ServiceDetails::ValidatorStatus(details) = &service.details {
                Some((service, details))
            } else {
                None
            }
        })
        .collect();
    let counts = HealthCounts::from_statuses(snapshot.services.iter().map(|s| &s.status));
    let total = counts.total();
    let service_count = if total == 1 {
        "1 Service".to_owned()
    } else {
        format!("{total} Services")
    };
    let status = counts.status();
    let class = status_class(&status);
    let overall = match status {
        Status::Healthy => "All Systems Operational".to_owned(),
        Status::Unhealthy => format!("{} unhealthy", counts.unhealthy),
        Status::Unknown if total == 0 => "No services configured".to_owned(),
        Status::Unknown => format!("{} unknown", counts.unknown),
    };
    html! {
        main class="dashboard" {
            div class="title" {
                h1 class="form-title" { "Network Status Dashboard" }
                p class={"overall-status " (class)} {
                    span class="pulse" {}
                    (overall)
                    @if total > 0 { " · " (service_count) }
                }
            }
            div class="status-grid" {
                @for service in &snapshot.services {
                    @if !matches!(service.details, ServiceDetails::ValidatorStatus(_)) {
                        (service_card(service, rpc_chain_tip))
                    }
                }
            }
            @if !validators.is_empty() {
                (cards::render_validators(&validators))
            }
            button class="button" type="button"
                hx-get="/fragments/status"
                hx-target="#status-container"
                hx-swap="innerHTML"
            {
                svg class="button-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" aria-hidden="true" {
                    path d="M13.5 8A5.5 5.5 0 1 1 11.9 4.1M13.5 2v3h-3" {}
                }
                "Refresh Status"
            }
            div class="note" {
                "Last updated: " (format_timestamp(snapshot.last_updated))
            }
        }
        (footer(&snapshot.monitor_version, &service_count, class, &overall))
    }
}

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

// CARD CHROME + DISPATCHER
// ================================================================================================

/// Wraps any service in the uniform card chrome (header with status badge, body via
/// [`render_details`], timestamp footer).
fn service_card(service: &ServiceStatus, rpc_chain_tip: Option<u32>) -> Markup {
    let class = status_class(&service.status);
    html! {
        div class="service-card" {
            div class="service-header" {
                div class="service-name" { (service.name) }
                div class={"service-status " (class)} {
                    (status_label(&service.status))
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

/// Dispatches to the per-service renderer in [`cards`] based on the [`ServiceDetails`] variant.
/// Cards may emit `data-grpc-url` / `data-grpc-path` attributes that `probes.js` reads to issue
/// browser-side gRPC-Web probes.
fn render_details(service: &ServiceStatus, rpc_chain_tip: Option<u32>) -> Markup {
    let healthy = matches!(service.status, Status::Healthy);
    match &service.details {
        ServiceDetails::RpcStatus(d) => cards::render_rpc_status(d),
        ServiceDetails::RemoteProverStatus(d) => cards::render_remote_prover(d),
        ServiceDetails::FaucetTest(d) => cards::render_faucet_test(d, healthy),
        ServiceDetails::FundingStatus(d) => cards::render_funding_service(d, healthy),
        ServiceDetails::NtxIncrement(d) => cards::render_ntx_increment(d, healthy),
        ServiceDetails::NtxTracking(d) => cards::render_ntx_tracking(d, healthy),
        ServiceDetails::ExplorerStatus(d) => cards::render_explorer(d, rpc_chain_tip, healthy),
        ServiceDetails::NoteTransportStatus(d) => cards::render_note_transport(d, healthy),
        // Validators share a card rendered by `status_fragment`.
        ServiceDetails::ValidatorStatus(_) => html! {},
        ServiceDetails::AgglayerStatus(d) => cards::render_agglayer(d),
        ServiceDetails::UsdcxBridge(d) => cards::render_usdcx_bridge(d),
        ServiceDetails::Error => html! {},
    }
}

// FOOTER
// ================================================================================================

fn footer(version: &str, service_count: &str, class: &str, overall: &str) -> Markup {
    html! {
        footer class="footer" {
            div class="footer-content" {
                div class="footer-section" {
                    div class="footer-label" { "Network Status" }
                    div class={"footer-value " (class)} { (overall) }
                }
                div class="footer-section footer-center" {
                    div class="footer-value" {
                        @if !version.is_empty() {
                            "Monitor v" (version)
                        }
                    }
                }
                div class="footer-section tokens-section" {
                    div class="footer-label" { "Services" }
                    div class="footer-value" { (service_count) }
                }
            }
            div class="footer-line" {}
        }
    }
}

// CROSS-SERVICE LOOKUP
// ================================================================================================

fn find_rpc_chain_tip(services: &[ServiceStatus]) -> Option<u32> {
    for service in services {
        if let ServiceDetails::RpcStatus(rpc) = &service.details {
            return Some(rpc.chain_tip);
        }
    }
    None
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use helpers::truncate;

    use super::*;
    use crate::faucet::{FaucetTestDetails, GetMetadataResponse};
    use crate::remote_prover::{ProofType, ProverTestDetails};
    use crate::status::{
        AgglayerDirectionDetails,
        AgglayerStatusDetails,
        BlockProducerStatusDetails,
        CounterTrackingDetails,
        ExplorerStatusDetails,
        IncrementDetails,
        MempoolStatusDetails,
        NoteTransportStatusDetails,
        ProverTestOutcome,
        RemoteProverDetails,
        RemoteProverStatusDetails,
        RpcStatusDetails,
        ValidatorStatusDetails,
        WorkerStatusDetails,
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
            chain_tip: 42,
            block_producer_status: Some(BlockProducerStatusDetails {
                version: "1.2.3".to_string(),
                status: Status::Healthy,
                chain_tip: 42,
                mempool: Some(MempoolStatusDetails {
                    uncommitted_transactions: 4,
                    unbatched_transactions: 1,
                    proposed_batches: 2,
                    proven_batches: 3,
                }),
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
            last_note_id: Some("deadbeef".to_string()),
            faucet_metadata: Some(GetMetadataResponse {
                version: "1.0".to_string(),
                id: "tokenid".to_string(),
                decimals: 8,
                explorer_url: Some("https://explorer.example".to_string()),
                pow_load_difficulty: 4,
                base_amount: 100,
                token_amounts: vec![100, 500],
                balance: Some(1_000_000),
            }),
        };
        let html = render(vec![healthy("faucet", ServiceDetails::FaucetTest(details))]);
        assert!(html.contains("Faucet:"));
        assert!(html.contains("Faucet Token Info"));
        assert!(html.contains("Last Note ID"));
        assert!(html.contains("0.01 tokens"));
        assert!(html.contains("0.000001 tokens"));
    }

    /// Metadata is fetched independently of the mint test, so an unhealthy faucet (minting failing)
    /// must still display the token info block. See issue #2256.
    #[test]
    fn renders_faucet_metadata_when_unhealthy() {
        let details = FaucetTestDetails {
            url: "https://faucet.example".to_string(),
            test_duration_ms: 12,
            success_count: 0,
            failure_count: 3,
            last_note_id: None,
            faucet_metadata: Some(GetMetadataResponse {
                version: "0.15.0".to_string(),
                id: "tokenid".to_string(),
                decimals: 8,
                explorer_url: None,
                pow_load_difficulty: 4,
                base_amount: 100,
                token_amounts: vec![100, 500],
                balance: None,
            }),
        };
        let status = ServiceStatus {
            name: "faucet".to_string(),
            status: Status::Unhealthy,
            last_checked: 1_609_459_200,
            error: Some("minting failed".to_string()),
            details: ServiceDetails::FaucetTest(details),
        };
        let html = render(vec![status]);
        assert!(html.contains("Faucet Token Info"));
        assert!(html.contains("0.15.0"));
        assert!(html.contains("tokenid"));
        assert!(html.contains("0.000001 tokens"));
        assert!(html.contains(&helpers::metric_row("Balance:", "-").into_string()));
    }

    #[test]
    fn renders_ntx_increment_card() {
        let details = IncrementDetails {
            success_count: 5,
            failure_count: 0,
            last_tx_id: Some("abc123".to_string()),
            last_latency_blocks: Some(2),
            fee_balance: None,
            fee_topup_error: None,
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
            total_transactions: 1,
            total_nullifiers: 1,
            total_notes: 1,
            total_account_updates: 1,
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
        let details = NoteTransportStatusDetails { url: "https://nt.example".to_string() };
        let html =
            render(vec![healthy("note-transport", ServiceDetails::NoteTransportStatus(details))]);
        assert!(html.contains("Note Transport"));
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
        assert!(html.contains("Validators"));
        assert!(html.contains("1/1 healthy"));
        assert!(html.contains("Version 1.0"));
        assert!(html.contains("Signed Blocks"));
        assert!(!html.contains("https://validator.example"));
        assert!(!html.contains("URL:"));
    }

    #[test]
    fn renders_named_validators_with_independent_health() {
        let services = vec![
            healthy(
                "Validator (Miden)",
                ServiceDetails::ValidatorStatus(ValidatorStatusDetails {
                    url: "https://miden.example".to_string(),
                    chain_tip: 42,
                    validated_transactions_count: 123,
                    signed_blocks_count: 21,
                    ..Default::default()
                }),
            ),
            healthy("rpc", ServiceDetails::RpcStatus(rpc_details())),
            ServiceStatus::unhealthy(
                "Validator (Gateway)",
                "connection refused",
                ServiceDetails::ValidatorStatus(ValidatorStatusDetails {
                    url: "https://gateway.example".to_string(),
                    ..Default::default()
                }),
            ),
        ];
        let html = render(services);
        assert_eq!(html.matches("aria-label=\"Validators\"").count(), 1);
        assert!(html.contains("1/2 healthy"));
        assert!(html.contains("Miden"));
        assert!(html.contains("Gateway"));
        assert!(html.contains("42"));
        assert!(html.contains("123"));
        assert!(html.contains("21"));
        assert!(html.contains("Mempool stats"));
        assert!(html.contains("View error for Gateway"));
        assert!(!html.contains("View error for Miden"));
        assert!(html.contains("connection refused"));
        assert!(html.contains(">Healthy<"));
        assert!(html.contains(">Unhealthy<"));
        assert!(!html.contains("https://miden.example"));
        assert!(!html.contains("https://gateway.example"));
    }

    #[test]
    fn validator_summary_distinguishes_pending_checks_from_failures() {
        let services = vec![
            healthy(
                "Validator (Miden)",
                ServiceDetails::ValidatorStatus(ValidatorStatusDetails::default()),
            ),
            ServiceStatus::unknown(
                "Validator (Gateway)",
                ServiceDetails::ValidatorStatus(ValidatorStatusDetails::default()),
            ),
        ];
        let html = render(services.clone());
        assert!(html.contains("1/2 healthy · 1 unknown"));
        assert!(html.contains(">Unknown<"));
        assert!(!html.contains(">Unhealthy<"));
        assert!(html.contains("1 unknown · 2 Services"));

        let mut services = services;
        services[1].status = Status::Healthy;
        let html = render(services);
        assert!(html.contains("2/2 healthy"));
        assert!(html.contains("All Systems Operational"));
    }

    #[test]
    fn no_validator_card_without_configured_validators() {
        let html = render(vec![healthy("rpc", ServiceDetails::RpcStatus(rpc_details()))]);
        assert!(!html.contains("Validators"));
    }

    #[test]
    fn renders_funding_status_and_unavailable_state() {
        use crate::funding_service::{FundingStatusResponse, NativeAsset};
        use crate::status::FundingStatusDetails;

        let details = FundingStatusDetails {
            url: "https://funding.example".to_string(),
            status: Some(FundingStatusResponse {
                version: "1.2.3".to_string(),
                account_id: "0x1234".to_string(),
                native_asset: NativeAsset {
                    asset_id: "0xabcd".to_string(),
                    name: "Miden".to_string(),
                    symbol: "MIDEN".to_string(),
                    decimals: 6,
                },
                balance: 123_456,
                chain_tip: 42,
                max_amount: 1000,
                verification_base_fee: 7,
            }),
        };
        let html = render(vec![healthy("Funding Service", ServiceDetails::FundingStatus(details))]);
        for expected in [
            "Funding Service",
            "https://funding.example",
            "1.2.3",
            "0x1234",
            "0xabcd",
            "MIDEN",
            "0.123456 MIDEN",
            "0.001 MIDEN",
            "0.000007 MIDEN",
            "Balance:",
            "Max Request:",
            "Verification Base Fee:",
        ] {
            assert!(html.contains(expected), "missing {expected}");
        }
        let html = render(vec![ServiceStatus::unhealthy(
            "Funding Service",
            "unreachable",
            ServiceDetails::FundingStatus(FundingStatusDetails {
                url: "https://funding.example".to_string(),
                status: None,
            }),
        )]);
        assert!(html.contains("https://funding.example"));
        assert!(html.contains("unreachable"));
        assert!(!html.contains("Balance:"));
    }

    #[test]
    fn renders_agglayer_card() {
        let details = AgglayerStatusDetails {
            url: "https://agglayer-monitor.example".to_string(),
            reason_code: None,
            runner_status: "running".to_string(),
            heartbeat_at: 1_609_459_200,
            inbound: AgglayerDirectionDetails {
                status: Status::Healthy,
                last_success_at: Some(1_609_459_200),
                last_success_duration_ms: Some(1_190_000),
                success_count: 1,
                ..Default::default()
            },
            outbound: AgglayerDirectionDetails {
                status: Status::Unhealthy,
                reason_code: Some("deadline_exceeded".to_string()),
                last_failure_at: Some(1_609_459_200),
                last_failure_code: Some("deadline_exceeded".to_string()),
                current_phase: Some("waiting_claimable".to_string()),
                failure_count: 1,
                ..Default::default()
            },
        };
        let html =
            render(vec![healthy("Agglayer Bridge", ServiceDetails::AgglayerStatus(details))]);
        assert!(html.contains("Agglayer Bridge"));
        assert!(html.contains("L1 → Miden:"));
        assert!(html.contains("Miden → L1:"));
        assert!(html.contains("2021-01-01 00:00:00 UTC"));
        assert!(html.contains("deadline_exceeded"));
        assert!(html.contains("waiting_claimable"));
        // Only the unhealthy outbound direction has a reason.
        assert_eq!(html.matches("Reason:").count(), 1);
    }

    #[test]
    fn renders_usdcx_bridge_card() {
        use crate::status::{
            UsdcxActivityDetails,
            UsdcxBridgeDetails,
            UsdcxBridgeEvent,
            UsdcxBridgeEventKind,
            UsdcxFaucetDetails,
            XReserveDetails,
        };

        let details = UsdcxBridgeDetails {
            xreserve_address: "0x008888878f94C0d87defdf0B07f46B93C1934442".to_string(),
            faucet: Some(UsdcxFaucetDetails {
                faucet_id: "0xfaucet".to_string(),
                block_num: 42,
                symbol: "USDCX".to_string(),
                decimals: 6,
                circulating_supply: 1_500_000,
                paused: false,
                circle_domain: 10_007,
            }),
            xreserve: Some(XReserveDetails {
                chain_id: 5_042_002,
                collateral: 2_000_000,
                collateral_decimals: 6,
                paused: false,
                deposits_paused: true,
                withdrawals_paused: false,
            }),
            activity: Some(UsdcxActivityDetails {
                deposits_24h: 3,
                withdrawals_24h: 1,
                latest: Some(UsdcxBridgeEvent {
                    kind: UsdcxBridgeEventKind::Withdrawal,
                    block_num: 40,
                    timestamp: 1_609_459_200,
                    transaction_id: "0xtransaction".to_string(),
                }),
                synced_to: 30,
                chain_tip: 42,
            }),
            activity_error: Some("failed to sync the faucet transactions".to_string()),
        };
        let html = render(vec![healthy("USDCx Bridge", ServiceDetails::UsdcxBridge(details))]);
        for expected in [
            "USDCx Bridge",
            "0xfaucet",
            "1.5 USDCX",
            "10007",
            "0x008888878f94C0d87defdf0B07f46B93C1934442",
            "5042002",
            "2 USDC",
            "0.5 USDC",
            "Paused",
            "Withdrawal at 2021-01-01 00:00:00 UTC (block 40)",
            "synced to block 30 of 42",
            "failed to sync the faucet transactions",
        ] {
            assert!(html.contains(expected), "missing {expected}");
        }
    }

    #[test]
    fn renders_usdcx_bridge_deficit_and_missing_reads() {
        use crate::status::{UsdcxBridgeDetails, UsdcxFaucetDetails, XReserveDetails};

        let faucet = UsdcxFaucetDetails {
            faucet_id: "0xfaucet".to_string(),
            block_num: 42,
            symbol: "USDCX".to_string(),
            decimals: 6,
            circulating_supply: 3_000_000,
            paused: false,
            circle_domain: 10_007,
        };
        let xreserve = XReserveDetails {
            chain_id: 5_042_002,
            collateral: 2_000_000,
            collateral_decimals: 6,
            paused: false,
            deposits_paused: false,
            withdrawals_paused: false,
        };
        let deficit = UsdcxBridgeDetails {
            faucet: Some(faucet),
            xreserve: Some(xreserve),
            ..Default::default()
        };
        let html = render(vec![ServiceStatus::unhealthy(
            "USDCx Bridge",
            "supply exceeds collateral",
            ServiceDetails::UsdcxBridge(deficit),
        )]);
        assert!(html.contains("-1 USDC (deficit)"));

        let html = render(vec![ServiceStatus::unhealthy(
            "USDCx Bridge",
            "connection refused",
            ServiceDetails::UsdcxBridge(UsdcxBridgeDetails::default()),
        )]);
        assert!(html.contains("connection refused"));
        assert!(html.contains(&helpers::metric_row("Circulating Supply:", "-").into_string()));
        assert!(html.contains(&helpers::metric_row("Collateral:", "-").into_string()));
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
        assert!(html.contains("Unhealthy"));
        assert!(html.contains("boom"));
    }

    #[test]
    fn refreshed_dashboard_reports_failures_even_with_checks_pending() {
        let html = render(vec![
            ServiceStatus::unknown("pending", ServiceDetails::Error),
            ServiceStatus::unhealthy("failed", "connection refused", ServiceDetails::Error),
        ]);
        let (dashboard, footer) = html.split_once("<footer").expect("refreshed footer");
        assert!(dashboard.contains("1 unhealthy · 2 Services"));
        assert!(footer.contains("1 unhealthy"));
    }

    #[test]
    fn empty_dashboard_explains_why_health_is_unknown() {
        assert!(render(vec![]).contains("No services configured"));
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
        // past the lag tolerance baked into the explorer card.
        let explorer = ExplorerStatusDetails::default();
        let html = render(vec![
            healthy("rpc", ServiceDetails::RpcStatus(rpc_details())),
            healthy("explorer", ServiceDetails::ExplorerStatus(explorer)),
        ]);
        assert!(html.contains("Explorer tip is"));
        assert!(html.contains("behind"));
    }
}
