//! Server-side HTML rendering for the network monitor dashboard.
//!
//! [`page`] returns the full HTML document; [`status_fragment`] returns just the cards grid that
//! htmx swaps into `#status-container` on each poll.

mod cards;
mod helpers;

use helpers::format_timestamp;
use maud::{DOCTYPE, Markup, html};

use crate::frontend::ServerState;
use crate::status::{
    NetworkStatus,
    ServiceDetails,
    ServiceStatus,
    Status,
    current_unix_timestamp_secs,
};

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

/// Dispatches to the per-service renderer in [`cards`] based on the [`ServiceDetails`] variant.
/// Cards may emit `data-grpc-url` / `data-grpc-path` attributes that `probes.js` reads to issue
/// browser-side gRPC-Web probes.
fn render_details(service: &ServiceStatus, rpc_chain_tip: Option<u32>) -> Markup {
    let healthy = matches!(service.status, Status::Healthy);
    match &service.details {
        ServiceDetails::RpcStatus(d) => cards::render_rpc_status(d),
        ServiceDetails::RemoteProverStatus(d) => cards::render_remote_prover(d),
        ServiceDetails::FaucetTest(d) => cards::render_faucet_test(d, healthy),
        ServiceDetails::NtxIncrement(d) => cards::render_ntx_increment(d, healthy),
        ServiceDetails::NtxTracking(d) => cards::render_ntx_tracking(d, healthy),
        ServiceDetails::ExplorerStatus(d) => cards::render_explorer(d, rpc_chain_tip, healthy),
        ServiceDetails::NoteTransportStatus(d) => cards::render_note_transport(d, healthy),
        ServiceDetails::ValidatorStatus(d) => cards::render_validator(d, healthy),
        ServiceDetails::Error => html! {},
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

// CROSS-SERVICE LOOKUP
// ================================================================================================

/// Returns the chain tip reported by the first RPC service in the snapshot, preferring the store
/// over the block-producer. Used by the explorer card to flag when the explorer's tip drifts past
/// its tolerance vs. the RPC's view.
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
    use helpers::truncate;

    use super::*;
    use crate::faucet::{FaucetTestDetails, GetMetadataResponse};
    use crate::remote_prover::{ProofType, ProverTestDetails};
    use crate::status::{
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
        StoreStatusDetails,
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
                note_transport_url: Some("https://note-transport.example".to_string()),
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
