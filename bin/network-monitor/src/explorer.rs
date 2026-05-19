// EXPLORER STATUS CHECKER
// ================================================================================================

use std::fmt::{self, Display};
use std::time::Duration;

use reqwest::Client;
use serde::Serialize;
use tracing::instrument;
use url::Url;

use crate::COMPONENT;
use crate::service::Service;
use crate::status::{ExplorerStatusDetails, ServiceDetails, ServiceStatus};

const LATEST_BLOCK_QUERY: &str = "
query LatestBlock {
    blocks(input: { sort_by: timestamp, order_by: desc }, first: 1) {
        edges {
            node {
                block_number
                timestamp
                number_of_transactions
                number_of_nullifiers
                number_of_notes
                block_commitment
                chain_commitment
                proof_commitment
                number_of_account_updates
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

const LATEST_BLOCK_REQUEST: GraphqlRequest<EmptyVariables> = GraphqlRequest {
    query: LATEST_BLOCK_QUERY,
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

    #[instrument(target = COMPONENT, name = "check-status.explorer", skip_all, ret(level = "info"))]
    async fn check(&mut self) -> ServiceStatus {
        let resp = self
            .client
            .post(self.url.clone())
            .json(&LATEST_BLOCK_REQUEST)
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

        let value: serde_json::Value = match serde_json::from_str(&body) {
            Ok(value) => value,
            Err(e) => return ServiceStatus::error(self.name(), format!("{e}: {body}")),
        };

        match ExplorerStatusDetails::try_from(value) {
            Ok(details) => {
                ServiceStatus::healthy(self.name(), ServiceDetails::ExplorerStatus(details))
            },
            Err(e) => ServiceStatus::error(self.name(), e),
        }
    }
}

#[derive(Debug)]
pub enum ExplorerStatusError {
    /// A required field was not present in the response.
    NotPresent { field: String, response: String },
    /// A field was present but had an unexpected type.
    TypeMismatch {
        field: String,
        expected: &'static str,
        got: String,
    },
}

impl Display for ExplorerStatusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExplorerStatusError::NotPresent { field, response } => {
                write!(f, "field '{field}': not present in response (got: {response})")
            },
            ExplorerStatusError::TypeMismatch { field, expected, got } => {
                write!(f, "field '{field}': expected {expected}, got {got}")
            },
        }
    }
}

/// Extracts a u64 from a named field.
///
/// Accepts both numeric values and string-encoded numbers (as returned by the Explorer's
/// GraphQL API).
fn require_u64(node: &serde_json::Value, field: &str) -> Result<u64, ExplorerStatusError> {
    let value = node.get(field).ok_or_else(|| ExplorerStatusError::NotPresent {
        field: field.into(),
        response: truncate_json(node),
    })?;

    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|s| s.parse().ok()))
        .ok_or_else(|| ExplorerStatusError::TypeMismatch {
            field: field.into(),
            expected: "u64-compatible value",
            got: truncate_json(value),
        })
}

/// Extracts a string from a named field.
fn require_str(node: &serde_json::Value, field: &str) -> Result<String, ExplorerStatusError> {
    let value = node.get(field).ok_or_else(|| ExplorerStatusError::NotPresent {
        field: field.into(),
        response: truncate_json(node),
    })?;

    value
        .as_str()
        .map(String::from)
        .ok_or_else(|| ExplorerStatusError::TypeMismatch {
            field: field.into(),
            expected: "string",
            got: truncate_json(value),
        })
}

/// Returns a short string representation of a JSON value for error messages.
///
/// Truncates the JSON string to at most 60 characters, appending "..." if truncated.
/// Truncation is done at a character boundary to avoid panicking on multi-byte characters.
fn truncate_json(value: &serde_json::Value) -> String {
    let s = value.to_string();
    match s.char_indices().nth(60) {
        Some((idx, _)) => format!("{}...", &s[..idx]),
        None => s,
    }
}

impl TryFrom<serde_json::Value> for ExplorerStatusDetails {
    type Error = ExplorerStatusError;

    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        let node = value.pointer("/data/blocks/edges/0/node").ok_or_else(|| {
            ExplorerStatusError::NotPresent {
                field: "data.blocks.edges[0].node".to_string(),
                response: truncate_json(&value),
            }
        })?;

        Ok(Self {
            block_number: require_u64(node, "block_number")?,
            timestamp: require_u64(node, "timestamp")?,
            number_of_transactions: require_u64(node, "number_of_transactions")?,
            number_of_nullifiers: require_u64(node, "number_of_nullifiers")?,
            number_of_notes: require_u64(node, "number_of_notes")?,
            number_of_account_updates: require_u64(node, "number_of_account_updates")?,
            block_commitment: require_str(node, "block_commitment")?,
            chain_commitment: require_str(node, "chain_commitment")?,
            proof_commitment: require_str(node, "proof_commitment")?,
        })
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    // truncate_json tests
    // --------------------------------------------------------------------------------------------

    #[test]
    fn truncate_json_short_value_is_not_truncated() {
        let value = json!({"key": "short"});
        let result = truncate_json(&value);
        assert_eq!(result, value.to_string());
        assert!(!result.ends_with("..."));
    }

    #[test]
    fn truncate_json_long_value_is_truncated() {
        let long_string = "a".repeat(100);
        let value = json!(long_string);
        let result = truncate_json(&value);
        assert!(result.ends_with("..."));
        // 60 chars + "..."
        assert_eq!(result.chars().count(), 63);
    }

    #[test]
    fn truncate_json_multibyte_chars_are_handled() {
        // Each 'é' is 2 bytes in UTF-8. Build a string whose serialized JSON form exceeds 60
        // characters, ensuring truncation lands on a char boundary.
        let multibyte_string = "é".repeat(80);
        let value = json!(multibyte_string);
        // Should not panic and should still truncate correctly.
        let result = truncate_json(&value);
        assert!(result.ends_with("..."));
    }

    #[test]
    fn truncate_json_exactly_60_chars_is_not_truncated() {
        // Build a JSON string whose serialized form is exactly 60 characters. json!("x".repeat(58))
        // serializes as `"xxx...xxx"` (58 chars + 2 quotes = 60).
        let value = json!("x".repeat(58));
        let result = truncate_json(&value);
        assert_eq!(result.chars().count(), 60);
        assert!(!result.ends_with("..."));
    }

    // require_u64 tests
    // --------------------------------------------------------------------------------------------

    #[test]
    fn require_u64_from_number() {
        let node = json!({"block_number": 42});
        assert_eq!(require_u64(&node, "block_number").unwrap(), 42);
    }

    #[test]
    fn require_u64_from_string() {
        let node = json!({"block_number": "42"});
        assert_eq!(require_u64(&node, "block_number").unwrap(), 42);
    }

    #[test]
    fn require_u64_missing_field() {
        let node = json!({});
        let err = require_u64(&node, "block_number").unwrap_err();
        assert!(
            matches!(err, ExplorerStatusError::NotPresent { field, .. } if field == "block_number")
        );
    }

    #[test]
    fn require_u64_wrong_type() {
        let node = json!({"block_number": [1, 2, 3]});
        let err = require_u64(&node, "block_number").unwrap_err();
        assert!(
            matches!(err, ExplorerStatusError::TypeMismatch { field, .. } if field == "block_number")
        );
    }

    // require_str tests
    // --------------------------------------------------------------------------------------------

    #[test]
    fn require_str_valid() {
        let node = json!({"name": "hello"});
        assert_eq!(require_str(&node, "name").unwrap(), "hello");
    }

    #[test]
    fn require_str_missing_field() {
        let node = json!({});
        let err = require_str(&node, "name").unwrap_err();
        assert!(matches!(err, ExplorerStatusError::NotPresent { field, .. } if field == "name"));
    }

    #[test]
    fn require_str_wrong_type() {
        let node = json!({"name": 123});
        let err = require_str(&node, "name").unwrap_err();
        assert!(matches!(err, ExplorerStatusError::TypeMismatch { field, .. } if field == "name"));
    }
}
