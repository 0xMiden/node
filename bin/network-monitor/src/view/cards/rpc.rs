//! Renders the RPC service card. Embeds `data-grpc-url` so `probes.js` can issue a browser-side
//! probe to `/rpc.Api/Status`.

use maud::{Markup, html};

use super::super::helpers::{copy_button, metric_row, truncate};
use crate::status::RpcStatusDetails;

pub(in crate::view) fn render_rpc_status(details: &RpcStatusDetails) -> Markup {
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
