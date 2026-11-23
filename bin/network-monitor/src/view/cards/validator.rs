//! Renders independently monitored validators together for comparison.

use maud::{Markup, html};

use super::super::helpers::{
    HealthCounts,
    format_timestamp,
    num_or_dash,
    status_class,
    status_label,
};
use crate::status::{ServiceStatus, Status, ValidatorStatusDetails};

pub(in crate::view) fn render_validators(
    validators: &[(&ServiceStatus, &ValidatorStatusDetails)],
) -> Markup {
    let counts = HealthCounts::from_statuses(validators.iter().map(|(service, _)| &service.status));
    let overall_class = status_class(&counts.status());
    html! {
        section class={"service-card validators-card " (overall_class)} aria-label="Validators" {
            div class="service-header" {
                div class="service-name" { "Validators" }
                div class={"service-status validator-summary " (overall_class)} {
                    (counts.healthy) "/" (counts.total()) " healthy"
                    @if counts.unknown > 0 { " · " (counts.unknown) " unknown" }
                }
            }
            table class="validators-table" {
                thead {
                    tr {
                        th scope="col" { "Name" }
                        th scope="col" { "Health" }
                        th scope="col" { "Chain Tip" }
                        th scope="col" { "Validated Transactions" }
                        th scope="col" { "Signed Blocks" }
                    }
                }
                @for (index, (service, details)) in validators.iter().enumerate() {
                    @let name = service.name.strip_prefix("Validator (")
                        .and_then(|name| name.strip_suffix(')')).unwrap_or(&service.name);
                    @let healthy = service.status == Status::Healthy;
                    tbody {
                        tr {
                            th scope="row" {
                                div class="validator-name" {
                                    @if let Some(initial) = name.chars().next() {
                                        span class="validator-avatar" aria-hidden="true" { (initial) }
                                    }
                                    div {
                                        (name)
                                        @if !details.version.is_empty() {
                                            div class="validator-meta" { "Version " (details.version) }
                                        }
                                        div class="validator-meta" {
                                            "Last checked: " (format_timestamp(service.last_checked))
                                        }
                                    }
                                }
                            }
                            td data-label="Health" {
                                span class={"service-status " (status_class(&service.status))} { (status_label(&service.status)) }
                            }
                            td data-label="Chain Tip" { (num_or_dash(u64::from(details.chain_tip), healthy)) }
                            td data-label="Validated Transactions" { (num_or_dash(details.validated_transactions_count, healthy)) }
                            td data-label="Signed Blocks" { (num_or_dash(details.signed_blocks_count, healthy)) }
                        }
                        @if let Some(error) = &service.error {
                            tr class="validator-error-row" {
                                td colspan="5" {
                                    details class="validator-error" id={"validator-error-" (index)} {
                                        summary { "View error for " (name) }
                                        div class="error-message" { (error) }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
