//! Renders the Agglayer bridge card: agglayer-monitor runner info plus the latest E2E test results
//! for each bridge direction.

use maud::{Markup, html};

use super::super::helpers::{
    copy_button,
    format_success_rate,
    format_timestamp,
    metric_row,
    status_label,
};
use crate::status::{AgglayerDirectionDetails, AgglayerStatusDetails, Status};

pub(in crate::view) fn render_agglayer(details: &AgglayerStatusDetails) -> Markup {
    html! {
        div class="service-details" {
            div class="detail-item" {
                strong { "URL: " }
                (details.url)
                (copy_button(&details.url, "URL"))
            }
            div class="detail-item" {
                strong { "Runner: " }
                (or_dash(Some(details.runner_status.as_str())))
            }
            div class="detail-item" {
                strong { "Heartbeat: " }
                (format_timestamp(details.heartbeat_at))
            }
            @if let Some(reason) = &details.reason_code {
                div class="detail-item" {
                    strong { "Reason: " }
                    (reason)
                }
            }
            (render_direction("L1 → Miden:", &details.inbound))
            (render_direction("Miden → L1:", &details.outbound))
        }
    }
}

fn render_direction(title: &str, direction: &AgglayerDirectionDetails) -> Markup {
    let metrics_class = if matches!(direction.status, Status::Healthy) {
        "test-metrics healthy"
    } else {
        "test-metrics unhealthy"
    };
    let last_success = direction.last_success_at.map_or_else(|| "-".to_string(), format_timestamp);
    let last_failure = match (direction.last_failure_at, &direction.last_failure_code) {
        (Some(at), Some(code)) => format!("{} ({code})", format_timestamp(at)),
        (Some(at), None) => format_timestamp(at),
        (None, _) => "-".to_string(),
    };
    html! {
        div class="nested-status" {
            strong { (title) }
            div class=(metrics_class) {
                (metric_row("Status:", status_label(&direction.status)))
                @if let Some(reason) = &direction.reason_code {
                    (metric_row("Reason:", reason))
                }
                (metric_row("Last Success:", &last_success))
                (metric_row("Last Failure:", &last_failure))
                @if let Some(phase) = &direction.current_phase {
                    (metric_row("Current Phase:", phase))
                }
                (metric_row(
                    "Success Rate:",
                    &format_success_rate(direction.success_count, direction.failure_count),
                ))
            }
        }
    }
}

fn or_dash(value: Option<&str>) -> &str {
    match value {
        Some(value) if !value.is_empty() => value,
        _ => "-",
    }
}
