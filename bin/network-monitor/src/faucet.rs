//! Faucet testing functionality.
//!
//! This module contains the logic for periodically testing faucet functionality
//! by requesting proof-of-work challenges, solving them, and submitting token requests.

use std::time::{Duration, Instant};

use anyhow::Context;
use hex;
use miden_node_utils::spawn::spawn_blocking_in_current_span;
use miden_node_utils::tracing::miden_instrument;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};
use url::Url;

use crate::COMPONENT;
use crate::deploy::wallet::create_wallet_account;
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
    /// Wall-clock cap on solving a single `PoW` challenge.
    solve_timeout: Duration,
    /// A valid public account ID used as the recipient for faucet token requests. Generated once at
    /// construction from a throwaway wallet account; the minted tokens are never spent.
    account_id: String,
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
        let (wallet_account, _secret_key) =
            create_wallet_account().expect("failed to create faucet recipient account");
        Self {
            url,
            client,
            interval,
            solve_timeout: request_timeout,
            account_id: wallet_account.id().to_string(),
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

        // Fetch metadata independently of the mint test so that token info (account id, version, …)
        // is shown on the card even when minting is failing. We only overwrite the stored metadata
        // on a successful fetch, so a transient metadata errors doesn't wipe the last-known values
        // from the card.
        match fetch_faucet_metadata(&self.client, &self.url).await {
            Ok(metadata) => self.faucet_metadata = Some(metadata),
            Err(e) => warn!("Failed to fetch faucet metadata: {e:#}"),
        }

        let last_error =
            match perform_mint_test(&self.client, &self.url, &self.account_id, self.solve_timeout)
                .await
            {
                Ok(minted_tokens) => {
                    self.success_count += 1;
                    self.last_tx_id = Some(minted_tokens.tx_id.clone());
                    info!("Faucet test successful: tx_id={}", minted_tokens.tx_id);
                    None
                },
                Err(e) => {
                    self.failure_count += 1;
                    warn!("Faucet test failed: {}", e);
                    Some(format!("{e:#}"))
                },
            };

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

/// Fetches the faucet's metadata from the `/get_metadata` endpoint.
#[miden_instrument(
    parent = None,
    target = COMPONENT,
    name = "network_monitor.faucet.fetch_faucet_metadata",
    skip_all,
    level = "info",
    ret(level = "debug"),
    err,
)]
async fn fetch_faucet_metadata(
    client: &Client,
    faucet_url: &Url,
) -> anyhow::Result<GetMetadataResponse> {
    let metadata_url = faucet_url.join("/get_metadata")?;

    let response = client.get(metadata_url).send().await?;

    let response_text =
        read_success_body(response).await.context("/get_metadata request failed")?;

    parse_faucet_response(&response_text).context("unexpected response from /get_metadata")
}

/// Performs a complete faucet mint test by requesting a `PoW` challenge and submitting the
/// solution.
///
/// # Arguments
///
/// * `client` - The HTTP client to use.
/// * `faucet_url` - The URL of the faucet service.
///
/// # Returns
///
/// The response from the faucet if successful, or an error if the test fails.
#[miden_instrument(
    parent = None,
    target = COMPONENT,
    name = "network_monitor.faucet.perform_mint_test",
    skip_all,
    level = "info",
    ret(level = "debug"),
    err,
)]
async fn perform_mint_test(
    client: &Client,
    faucet_url: &Url,
    account_id: &str,
    solve_timeout: Duration,
) -> anyhow::Result<GetTokensResponse> {
    debug!("Using recipient account ID: {} (length: {})", account_id, account_id.len());

    // Step 1: Request PoW challenge
    let mut pow_url = faucet_url.join("/pow")?;
    pow_url
        .query_pairs_mut()
        .append_pair("account_id", account_id)
        .append_pair("amount", &MINT_AMOUNT.to_string());

    let response = client.get(pow_url).send().await?;

    let response_text = read_success_body(response).await.context("/pow request failed")?;
    debug!("Faucet PoW response: {}", response_text);

    let challenge_response: PowChallengeResponse =
        parse_faucet_response(&response_text).context("unexpected response from /pow")?;

    debug!(
        "Received PoW challenge: target={}, challenge={}...",
        challenge_response.target,
        &challenge_response.challenge[..16.min(challenge_response.challenge.len())]
    );

    // Step 2: Solve the PoW challenge off the async runtime; hashing is CPU-bound and would
    // otherwise stall every other checker task scheduled on this worker thread.
    let challenge = challenge_response.challenge.clone();
    let target = challenge_response.target;
    let nonce = spawn_blocking_in_current_span(move || {
        solve_pow_challenge(&challenge, target, solve_timeout)
    })
    .await
    .context("PoW solver task panicked")?
    .context("Failed to solve PoW challenge")?;

    debug!("Solved PoW challenge with nonce: {}", nonce);

    // Step 3: Request tokens with the solution
    let mut tokens_url = faucet_url.join("/get_tokens")?;
    tokens_url
        .query_pairs_mut()
        .append_pair("account_id", account_id)
        .append_pair("is_private_note", "false")
        .append_pair("asset_amount", &MINT_AMOUNT.to_string())
        .append_pair("challenge", &challenge_response.challenge)
        .append_pair("nonce", &nonce.to_string());

    let response = client.get(tokens_url).send().await?;

    let response_text = read_success_body(response).await.context("/get_tokens request failed")?;
    debug!("Faucet /get_tokens response: {}", response_text);

    let tokens_response: GetTokensResponse =
        parse_faucet_response(&response_text).context("unexpected response from /get_tokens")?;

    Ok(tokens_response)
}

/// Reads the response body, failing with the HTTP status code and body when the request was not
/// successful, so server-side errors (e.g. 429 or 500) surface directly on the card instead of as a
/// deserialization failure.
async fn read_success_body(response: reqwest::Response) -> anyhow::Result<String> {
    let status = response.status();
    let body = response.text().await?;
    anyhow::ensure!(status.is_success(), "HTTP {status}: {body}");
    Ok(body)
}

/// Deserialize a faucet response using [`serde_path_to_error`] so that the failing JSON path (e.g.
/// `max_supply`, `explorer_url`) is included in the error message. Combined with
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
/// This is CPU-bound and must run on a blocking thread (see the `spawn_blocking` call site).
///
/// # Arguments
///
/// * `challenge` - The challenge string in hexadecimal format.
/// * `target` - The target value. A solution is valid if H(challenge, nonce) < target.
/// * `timeout` - Wall-clock cap; checked every 100k attempts so a pathological difficulty cannot
///   pin the blocking thread indefinitely.
///
/// # Returns
///
/// The nonce that solves the challenge, or an error if no solution is found within the attempt
/// and time bounds.
#[miden_instrument(
    parent = None,
    target = COMPONENT,
    name = "network_monitor.faucet.solve_pow_challenge",
    skip_all,
    level = "info",
    ret(level = "debug"),
    err,
)]
fn solve_pow_challenge(challenge: &str, target: u64, timeout: Duration) -> anyhow::Result<u64> {
    let challenge_bytes = hex::decode(challenge).context("Failed to decode challenge from hex")?;
    let started = Instant::now();

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

        // Check the deadline and log progress every 100k attempts
        if nonce % 100_000 == 0 && nonce > 0 {
            let elapsed = started.elapsed();
            if elapsed >= timeout {
                anyhow::bail!(
                    "Failed to solve PoW challenge within {timeout:?} ({nonce} attempts, target \
                     {target})"
                );
            }
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
