// EXPLORER STATUS CHECKER
// ================================================================================================

use std::time::Duration;

use anyhow::Context;
use miden_node_utils::tracing::miden_instrument;
use reqwest::Client;
use serde::{Deserialize, Deserializer, Serialize};
use url::Url;

use crate::COMPONENT;
use crate::service::Service;
use crate::status::{ExplorerStatusDetails, ServiceDetails, ServiceStatus};

/// Fetches network-wide totals from `overviewStats` together with the latest block header (number +
/// timestamp + commitments). The latest block is still needed for tip-drift detection against the
/// RPC.
const NETWORK_OVERVIEW_QUERY: &str = "
query NetworkOverview {
    overviewStats {
        total_count_transactions
        total_count_nullifiers
        total_count_notes
        total_count_account_updates
    }
    blocks(input: { sort_by: timestamp, order_by: desc }, first: 1) {
        edges {
            node {
                block_number
                timestamp
                block_commitment
                chain_commitment
                proof_commitment
            }
        }
    }
}
";

#[derive(Serialize, Copy, Clone)]
struct EmptyVariables;

#[derive(Serialize, Copy, Clone)]
struct GraphqlRequest<V> {
    query: &'static str,
    variables: V,
}

const NETWORK_OVERVIEW_REQUEST: GraphqlRequest<EmptyVariables> = GraphqlRequest {
    query: NETWORK_OVERVIEW_QUERY,
    variables: EmptyVariables,
};

pub struct ExplorerService {
    url: Url,
    client: Client,
    interval: Duration,
    request_timeout: Duration,
}

impl ExplorerService {
    pub fn new(url: Url, interval: Duration, request_timeout: Duration) -> Self {
        Self {
            url,
            client: reqwest::Client::new(),
            interval,
            request_timeout,
        }
    }
}

impl Service for ExplorerService {
    fn name(&self) -> &'static str {
        "Explorer"
    }

    fn interval(&self) -> Duration {
        self.interval
    }

    fn initial_status(&self) -> ServiceStatus {
        ServiceStatus::unknown(
            self.name(),
            ServiceDetails::ExplorerStatus(ExplorerStatusDetails::default()),
        )
    }

    #[miden_instrument(
        target = COMPONENT,
        name = "check-status.explorer",
        skip_all,
        ret(level = "info"),
    )]
    async fn check(&mut self) -> ServiceStatus {
        let resp = self
            .client
            .post(self.url.clone())
            .json(&NETWORK_OVERVIEW_REQUEST)
            .timeout(self.request_timeout)
            .send()
            .await;

        let body = match resp {
            Ok(resp) => match resp.text().await {
                Ok(body) => body,
                Err(e) => return ServiceStatus::error(self.name(), e),
            },
            Err(e) => return ServiceStatus::error(self.name(), e),
        };

        match parse_response(&body) {
            Ok(details) => {
                ServiceStatus::healthy(self.name(), ServiceDetails::ExplorerStatus(details))
            },
            Err(e) => ServiceStatus::error(self.name(), e),
        }
    }
}

/// Deserialize the GraphQL response and project it onto [`ExplorerStatusDetails`].
///
/// Uses [`serde_path_to_error`] so that failures point at the specific JSON path that no longer
/// matches the expected shape (e.g. `data.overviewStats.total_count_transactions`). The structs
/// use `#[serde(deny_unknown_fields)]` so that unexpected additions surface in the same way.
fn parse_response(body: &str) -> anyhow::Result<ExplorerStatusDetails> {
    let mut de = serde_json::Deserializer::from_str(body);
    let response: GraphqlResponse<NetworkOverviewData> = serde_path_to_error::deserialize(&mut de)
        .with_context(|| format!("failed to parse explorer response: {body}"))?;

    let block = response
        .data
        .blocks
        .edges
        .into_iter()
        .next()
        .context("explorer returned no blocks")?
        .node;

    Ok(ExplorerStatusDetails {
        block_number: block.block_number,
        timestamp: block.timestamp,
        total_transactions: response.data.overview_stats.transactions,
        total_nullifiers: response.data.overview_stats.nullifiers,
        total_notes: response.data.overview_stats.notes,
        total_account_updates: response.data.overview_stats.account_updates,
        block_commitment: block.block_commitment,
        chain_commitment: block.chain_commitment,
        proof_commitment: block.proof_commitment,
    })
}

// RESPONSE TYPES
// ================================================================================================

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GraphqlResponse<T> {
    data: T,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkOverviewData {
    #[serde(rename = "overviewStats")]
    overview_stats: OverviewStats,
    blocks: BlockConnection,
}

/// The explorer's `BigIntStringScalar` fields are wire-encoded as strings, so we parse them via
/// [`u64_from_str`] rather than relying on serde's numeric deserialization.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OverviewStats {
    #[serde(rename = "total_count_transactions", deserialize_with = "u64_from_str")]
    transactions: u64,
    #[serde(rename = "total_count_nullifiers", deserialize_with = "u64_from_str")]
    nullifiers: u64,
    #[serde(rename = "total_count_notes", deserialize_with = "u64_from_str")]
    notes: u64,
    #[serde(rename = "total_count_account_updates", deserialize_with = "u64_from_str")]
    account_updates: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BlockConnection {
    edges: Vec<BlockEdge>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BlockEdge {
    node: BlockNode,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BlockNode {
    #[serde(deserialize_with = "u64_from_str")]
    block_number: u64,
    #[serde(deserialize_with = "u64_from_str")]
    timestamp: u64,
    block_commitment: String,
    chain_commitment: String,
    proof_commitment: String,
}

fn u64_from_str<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    let s = String::deserialize(d)?;
    s.parse().map_err(serde::de::Error::custom)
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_response() -> String {
        r#"{
            "data": {
                "overviewStats": {
                    "total_count_transactions": "241820",
                    "total_count_nullifiers": "53060",
                    "total_count_notes": "125701",
                    "total_count_account_updates": "241776"
                },
                "blocks": {
                    "edges": [{
                        "node": {
                            "block_number": "1211961",
                            "timestamp": "1779374922",
                            "block_commitment": "0x7306",
                            "chain_commitment": "0x11844a",
                            "proof_commitment": "0xc2014763"
                        }
                    }]
                }
            }
        }"#
        .to_string()
    }

    #[test]
    fn parse_full_response() {
        let details = parse_response(&sample_response()).unwrap();
        assert_eq!(details.block_number, 1_211_961);
        assert_eq!(details.timestamp, 1_779_374_922);
        assert_eq!(details.total_transactions, 241_820);
        assert_eq!(details.total_nullifiers, 53_060);
        assert_eq!(details.total_notes, 125_701);
        assert_eq!(details.total_account_updates, 241_776);
        assert_eq!(details.block_commitment, "0x7306");
        assert_eq!(details.chain_commitment, "0x11844a");
        assert_eq!(details.proof_commitment, "0xc2014763");
    }

    #[test]
    fn missing_field_error_includes_path() {
        let body = sample_response().replace("total_count_transactions", "txn_count");
        let err = parse_response(&body).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("data.overviewStats"),
            "error should locate the failing path, got: {msg}",
        );
    }

    #[test]
    fn unknown_field_is_rejected() {
        let body = sample_response().replace(
            "\"total_count_transactions\": \"241820\",",
            "\"total_count_transactions\": \"241820\", \"unexpected_field\": 1,",
        );
        let err = parse_response(&body).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("unexpected_field"),
            "error should name the unknown field, got: {msg}",
        );
    }

    #[test]
    fn empty_blocks_array_is_an_error() {
        let body = r#"{
            "data": {
                "overviewStats": {
                    "total_count_transactions": "1",
                    "total_count_nullifiers": "1",
                    "total_count_notes": "1",
                    "total_count_account_updates": "1"
                },
                "blocks": { "edges": [] }
            }
        }"#;
        let err = parse_response(body).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("no blocks"), "got: {msg}");
    }

    #[test]
    fn non_numeric_string_is_rejected() {
        let body = sample_response().replace("\"241820\"", "\"not-a-number\"");
        let err = parse_response(&body).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("total_count_transactions"),
            "error should point at the failing field, got: {msg}",
        );
    }
}
