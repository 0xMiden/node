//! Renders the RPC service card. Embeds `data-grpc-url` so `probes.js` can issue a browser-side
//! probe to `/miden.node.v1.NodeService/Status`.

use maud::{Markup, html};

use super::super::helpers::{copy_button, copyable_value, metric_row};
use crate::status::RpcStatusDetails;

pub(in crate::view) fn render_rpc_status(details: &RpcStatusDetails) -> Markup {
    html! {
        div class="service-details" data-grpc-url=(details.url) data-grpc-path="/miden.node.v1.NodeService/Status" {
            div class="detail-item" {
                strong { "URL: " }
                (copyable_value(&details.url, "URL"))
            }
            div class="detail-item" {
                strong { "Version: " }
                (details.version)
            }
            div class="detail-item" {
                strong { "Chain Tip: " }
                (details.chain_tip)
            }
            @if let Some(genesis) = &details.genesis_commitment {
                div class="detail-item" {
                    strong { "Genesis: " }
                    span class="value-text genesis-value" title=(genesis) { (genesis) }
                    (copy_button(genesis, "genesis commitment"))
                }
            }
            @if let Some(block_producer) = &details.block_producer_status {
                div class="nested-status" {
                    div class="detail-item" { strong { "Block Producer" } }
                    (metric_row("Version:", &block_producer.version))
                    (metric_row("Status:", &format!("{:?}", block_producer.status)))
                    (metric_row("Chain Tip:", &block_producer.chain_tip.to_string()))
                    div class="nested-status mempool-stats" {
                        strong { "Mempool stats:" }
                        @if let Some(mempool) = &block_producer.mempool {
                            (metric_row("Uncommitted TXs:", &mempool.uncommitted_transactions.to_string()))
                            (metric_row("Unbatched TXs:", &mempool.unbatched_transactions.to_string()))
                            (metric_row("Proposed Batches:", &mempool.proposed_batches.to_string()))
                            (metric_row("Proven Batches:", &mempool.proven_batches.to_string()))
                        } @else {
                            (metric_row("Uncommitted TXs:", "-"))
                            (metric_row("Unbatched TXs:", "-"))
                            (metric_row("Proposed Batches:", "-"))
                            (metric_row("Proven Batches:", "-"))
                        }
                    }
                }
            }
        }
    }
}
