//! Renders the note-transport card (URL + gRPC serving status).

use maud::{Markup, html};

use super::super::helpers::{copy_button, metric_row};
use crate::status::NoteTransportStatusDetails;

pub(in crate::view) fn render_note_transport(
    details: &NoteTransportStatusDetails,
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
