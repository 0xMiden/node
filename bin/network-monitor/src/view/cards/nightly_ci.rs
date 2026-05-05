//! Renders the external nightly-CI card. Shows the conclusion of the most recent scheduled
//! run of the configured workflow, with a link to the run on github.com.

use maud::{Markup, html};

use super::super::helpers::{format_timestamp, metric_row};
use crate::nightly_ci::{NightlyCiDetails, NightlyConclusion};

pub(in crate::view) fn render_nightly_ci(details: &NightlyCiDetails, healthy: bool) -> Markup {
    let metrics_class = if healthy {
        "test-metrics healthy"
    } else {
        "test-metrics unhealthy"
    };

    let conclusion_label = match &details.run_conclusion {
        NightlyConclusion::Success => "✅ success",
        NightlyConclusion::Failure => "❌ failure",
        NightlyConclusion::Cancelled => "⏹ cancelled",
        NightlyConclusion::TimedOut => "⌛ timed out",
        NightlyConclusion::InProgress => "⏳ in progress",
        NightlyConclusion::Unknown => "—",
    };

    let started_label = details
        .run_started_at_unix
        .map(format_timestamp)
        .unwrap_or_else(|| "-".to_string());

    let run_link = details.run_html_url.as_deref();
    let workflow_link = details.workflow_html_url.as_str();

    html! {
        div class="service-details" {
            div class="nested-status" {
                strong { "Nightly CI:" }
                div class=(metrics_class) {
                    (metric_row("Conclusion:", conclusion_label))
                    (metric_row("Started:", &started_label))
                    div class="metric-row" {
                        span class="metric-label" { "Workflow:" }
                        span class="metric-value" {
                            // External link out — no copy button; the run URL changes
                            // every nightly so caching it isn't useful.
                            a href=(workflow_link) target="_blank" rel="noopener" {
                                (workflow_link)
                            }
                        }
                    }
                    @if let Some(url) = run_link {
                        div class="metric-row" {
                            span class="metric-label" { "Latest run:" }
                            span class="metric-value" {
                                a href=(url) target="_blank" rel="noopener" { (url) }
                            }
                        }
                    }
                }
            }
        }
    }
}
