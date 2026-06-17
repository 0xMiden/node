//! Renders the remote-prover card: proxy info, worker list, and last proof-generation test outcome.
//! Embeds `data-grpc-url` for `/remote_prover.ProxyStatusApi/Status` browser probes.

use maud::{Markup, html};

use super::super::helpers::{
    copy_button,
    format_success_rate,
    metric_row,
    probe_section_placeholder,
    proof_type_label,
    status_label,
    truncate,
};
use crate::status::{ProverTestOutcome, RemoteProverDetails, Status, WorkerStatusDetails};

pub(in crate::view) fn render_remote_prover(details: &RemoteProverDetails) -> Markup {
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
