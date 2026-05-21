//! Faucet testing functionality.
//!
//! This module contains the logic for periodically testing faucet functionality
//! by requesting proof-of-work challenges, solving them, and submitting token requests.

use std::time::Duration;

use anyhow::Context;
use hex;
use miden_protocol::account::AccountId;
use miden_protocol::testing::account_id::ACCOUNT_ID_SENDER;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, info, instrument, warn};
use url::Url;

use crate::COMPONENT;
use crate::service::Service;
use crate::status::{ServiceDetails, ServiceStatus};

// CONSTANTS
// ================================================================================================

/// Maximum number of attempts to solve a `PoW` challenge.
const MAX_CHALLENGE_ATTEMPTS: u64 = 100_000_000;
/// Amount of tokens to mint.
const MINT_AMOUNT: u64 = 1_000_000; // 1 token with 6 decimals

// FAUCET TEST TYPES
// ================================================================================================

/// Details of a faucet test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaucetTestDetails {
    pub url: String,
    pub test_duration_ms: u64,
    pub success_count: u64,
    pub failure_count: u64,
    pub last_tx_id: Option<String>,
    pub faucet_metadata: Option<GetMetadataResponse>,
}

/// Response from the faucet's `/pow` endpoint.
///
/// `deny_unknown_fields` makes the monitor flag schema drift loudly — a new field on the faucet
/// response will fail deserialization and surface in the error message, instead of being
/// silently dropped.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PowChallengeResponse {
    challenge: String,
    target: u64,
    #[expect(dead_code)] // Timestamp is part of API response but not used
    timestamp: u64,
}

/// Response from the faucet's `/get_tokens` endpoint.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GetTokensResponse {
    tx_id: String,
    #[expect(dead_code)] // Note ID is part of API response but not used in monitoring
    note_id: String,
}

/// Response from the faucet's `/get_metadata` endpoint.
///
/// Field set mirrors the faucet's `GetMetadataResponse` in
/// `bin/faucet/src/api/get_metadata.rs` on the `next` branch. Keep these in sync; the
/// `deny_unknown_fields` attribute will surface any drift loudly.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetMetadataResponse {
    pub version: String,
    pub id: String,
    pub max_supply: u64,
    pub decimals: u8,
    pub explorer_url: Option<String>,
    pub pow_load_difficulty: u64,
    pub base_amount: u64,
    pub note_transport_url: Option<String>,
}

// FAUCET TEST TASK
// ================================================================================================

pub struct FaucetService {
    url: Url,
    client: Client,
    interval: Duration,
    success_count: u64,
    failure_count: u64,
    last_tx_id: Option<String>,
    faucet_metadata: Option<GetMetadataResponse>,
}

impl FaucetService {
    pub fn new(url: Url, interval: Duration, request_timeout: Duration) -> Self {
        let client = Client::builder()
            .timeout(request_timeout)
            .build()
            .expect("Failed to create HTTP client with timeout");
        Self {
            url,
            client,
            interval,
            success_count: 0,
            failure_count: 0,
            last_tx_id: None,
            faucet_metadata: None,
        }
    }
}

impl Service for FaucetService {
    fn name(&self) -> &'static str {
        "Faucet"
    }

    fn interval(&self) -> Duration {
        self.interval
    }

    fn initial_status(&self) -> ServiceStatus {
        ServiceStatus::unknown(
            self.name(),
            ServiceDetails::FaucetTest(FaucetTestDetails {
                url: self.url.to_string(),
                test_duration_ms: 0,
                success_count: 0,
                failure_count: 0,
                last_tx_id: None,
                faucet_metadata: None,
            }),
        )
    }

    async fn check(&mut self) -> ServiceStatus {
        let start_time = std::time::Instant::now();
        let mut last_error: Option<String> = None;

        match perform_faucet_test(&self.client, &self.url).await {
            Ok((minted_tokens, metadata)) => {
                self.success_count += 1;
                self.last_tx_id = Some(minted_tokens.tx_id.clone());
                self.faucet_metadata = Some(metadata);
                info!("Faucet test successful: tx_id={}", minted_tokens.tx_id);
            },
            Err(e) => {
                self.failure_count += 1;
                last_error = Some(format!("{e:#}"));
                warn!("Faucet test failed: {}", e);
            },
        }

        let details = ServiceDetails::FaucetTest(FaucetTestDetails {
            url: self.url.to_string(),
            test_duration_ms: start_time.elapsed().as_millis() as u64,
            success_count: self.success_count,
            failure_count: self.failure_count,
            last_tx_id: self.last_tx_id.clone(),
            faucet_metadata: self.faucet_metadata.clone(),
        });

        match last_error {
            Some(err) => ServiceStatus::unhealthy(self.name(), err, details),
            None => ServiceStatus::healthy(self.name(), details),
        }
    }
}

/// Performs a complete faucet test by requesting a `PoW` challenge and submitting the solution.
///
/// # Arguments
///
/// * `client` - The HTTP client to use.
/// * `faucet_url` - The URL of the faucet service.
///
/// # Returns
///
/// The response from the faucet if successful, or an error if the test fails.
#[instrument(
    parent = None,
    target = COMPONENT,
    name = "network_monitor.faucet.perform_faucet_test",
    skip_all,
    level = "info",
    ret(level = "debug"),
    err
)]
async fn perform_faucet_test(
    client: &Client,
    faucet_url: &Url,
) -> anyhow::Result<(GetTokensResponse, GetMetadataResponse)> {
    // Use a test account ID - convert to AccountId and format properly
    let account_id = AccountId::try_from(ACCOUNT_ID_SENDER)
        .context("Failed to create AccountId from test constant")?;

    let account_id = account_id.to_string();
    debug!("Generated account ID: {} (length: {})", account_id, account_id.len());

    // Step 1: Request PoW challenge
    let mut pow_url = faucet_url.join("/pow")?;
    pow_url
        .query_pairs_mut()
        .append_pair("account_id", &account_id)
        .append_pair("amount", &MINT_AMOUNT.to_string());

    let response = client.get(pow_url).send().await?;

    let response_text: String = response.text().await?;
    debug!("Faucet PoW response: {}", response_text);

    let challenge_response: PowChallengeResponse =
        parse_faucet_response(&response_text).context("unexpected response from /pow")?;

    debug!(
        "Received PoW challenge: target={}, challenge={}...",
        challenge_response.target,
        &challenge_response.challenge[..16.min(challenge_response.challenge.len())]
    );

    // Step 2: Solve the PoW challenge
    let nonce = solve_pow_challenge(&challenge_response.challenge, challenge_response.target)
        .context("Failed to solve PoW challenge")?;

    debug!("Solved PoW challenge with nonce: {}", nonce);

    // Step 3: Request tokens with the solution
    let mut tokens_url = faucet_url.join("/get_tokens")?;
    tokens_url
        .query_pairs_mut()
        .append_pair("account_id", account_id.as_str())
        .append_pair("is_private_note", "false")
        .append_pair("asset_amount", &MINT_AMOUNT.to_string())
        .append_pair("challenge", &challenge_response.challenge)
        .append_pair("nonce", &nonce.to_string());

    let response = client.get(tokens_url).send().await?;

    let response_text: String = response.text().await?;
    debug!("Faucet /get_tokens response: {}", response_text);

    let tokens_response: GetTokensResponse =
        parse_faucet_response(&response_text).context("unexpected response from /get_tokens")?;

    // Step 4: Get faucet metadata
    let metadata_url = faucet_url.join("/get_metadata")?;

    let response = client.get(metadata_url).send().await?;

    let response_text = response.text().await?;
    debug!("Faucet /get_metadata response: {}", response_text);

    let metadata: GetMetadataResponse =
        parse_faucet_response(&response_text).context("unexpected response from /get_metadata")?;

    Ok((tokens_response, metadata))
}

/// Deserialize a faucet response using [`serde_path_to_error`] so that the failing JSON path
/// (e.g. `max_supply`, `explorer_url`) is included in the error message. Combined with
/// `#[serde(deny_unknown_fields)]` on each response type, this means renamed, removed, or newly
/// added fields all surface a precise field name rather than a generic "unexpected response".
fn parse_faucet_response<T>(body: &str) -> anyhow::Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    let mut de = serde_json::Deserializer::from_str(body);
    serde_path_to_error::deserialize(&mut de).with_context(|| format!("response body: {body}"))
}

/// Solves a proof-of-work challenge using SHA-256 hashing.
///
/// # Arguments
///
/// * `challenge` - The challenge string in hexadecimal format.
/// * `target` - The target value. A solution is valid if H(challenge, nonce) < target.
///
/// # Returns
///
/// The nonce that solves the challenge, or an error if no solution is found within reasonable
/// bounds.
#[instrument(
    parent = None,
    target = COMPONENT,
    name = "network_monitor.faucet.solve_pow_challenge",
    skip_all,
    level = "info",
    ret(level = "debug"),
    err
)]
fn solve_pow_challenge(challenge: &str, target: u64) -> anyhow::Result<u64> {
    let challenge_bytes = hex::decode(challenge).context("Failed to decode challenge from hex")?;

    // Try up to 100 million nonces.
    for nonce in 0..MAX_CHALLENGE_ATTEMPTS {
        let mut hasher = Sha256::new();
        hasher.update(&challenge_bytes);
        hasher.update(nonce.to_be_bytes());
        let hash_result = hasher.finalize();

        // Convert first 8 bytes of hash to u64 for comparison with target
        let hash_as_u64 = u64::from_be_bytes(hash_result[..8].try_into().unwrap());

        if hash_as_u64 < target {
            debug!(
                "PoW solution found! nonce={}, hash={}, target={} (~{} bits)",
                nonce,
                hash_as_u64,
                target,
                target.leading_zeros(),
            );
            return Ok(nonce);
        }

        // Log progress every 100k attempts
        if nonce % 100_000 == 0 && nonce > 0 {
            debug!(
                "PoW attempt {}: current_hash={}, target={} (~{} bits)",
                nonce,
                hash_as_u64,
                target,
                target.leading_zeros(),
            );
        }
    }

    anyhow::bail!("Failed to solve PoW challenge within 100M attempts")
}
