//! Shared formatting helpers and the gRPC-Web probe placeholder used across cards.

use maud::{Markup, PreEscaped, html};
use time::OffsetDateTime;
use time::macros::format_description;

use crate::remote_prover::ProofType;
use crate::status::Status;

pub(super) const COPY_ICON_SVG: &str = r#"<svg class="copy-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>"#;

/// Standard label/value row used inside `nested-status` blocks.
pub(super) fn metric_row(label: &str, value: &str) -> Markup {
    html! {
        div class="metric-row" {
            span class="metric-label" { (label) }
            span class="metric-value" { (value) }
        }
    }
}

/// Inline copy-to-clipboard button. `label` appears in the tooltip ("Copy full {label}"); `value`
/// is the literal text written to the clipboard via the JS helper.
pub(super) fn copy_button(value: &str, label: &str) -> Markup {
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
pub(super) fn probe_section_placeholder() -> Markup {
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
pub(super) fn truncate(value: &str, max_len: usize) -> &str {
    if value.len() <= max_len {
        return value;
    }
    let mut end = max_len;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

/// Renders the numeric value when the service is healthy, otherwise `-`. Mirrors the convention
/// used across cards: stale numbers from an unhealthy probe are not shown.
pub(super) fn num_or_dash(value: u64, healthy: bool) -> String {
    if healthy { value.to_string() } else { "-".to_string() }
}

/// Renders a truncated commitment with copy button when healthy and non-empty, `-` otherwise.
pub(super) fn commitment_or_dash(value: &str, label: &str, healthy: bool) -> Markup {
    if healthy && !value.is_empty() {
        html! {
            (truncate(value, 20)) "..." (copy_button(value, label))
        }
    } else {
        html! { "-" }
    }
}

pub(super) fn format_success_rate(success: u64, failure: u64) -> String {
    let total = success + failure;
    if total == 0 {
        return "N/A".to_string();
    }
    #[expect(clippy::cast_precision_loss, reason = "display only")]
    let pct = (success as f64 / total as f64) * 100.0;
    format!("{pct:.1}%")
}

pub(super) fn proof_type_label(proof_type: &ProofType) -> &'static str {
    match proof_type {
        ProofType::Transaction => "Transaction",
        ProofType::Block => "Block",
        ProofType::Batch => "Batch",
    }
}

pub(super) fn status_label(status: &Status) -> &'static str {
    match status {
        Status::Healthy => "Healthy",
        Status::Unhealthy => "Unhealthy",
        Status::Unknown => "Unknown",
    }
}

fn json_string(value: &str) -> String {
    serde_json::to_string(value).expect("string serialisation is infallible")
}

pub(super) fn format_timestamp(secs: u64) -> String {
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
