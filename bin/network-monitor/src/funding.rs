//! Fee funding for the monitor's accounts.
//!
//! Fees are withdrawn from the executing account's vault, so on a fee-charging chain the
//! monitor's fresh accounts need the fee asset before they can transact. This module requests a
//! P2ID note which holds the fee asset and returns it for consumption as an unauthenticated input
//! note.
//!
//! The funding service is the only source of the fee asset. The chain's faucet is not used for
//! fees, because a network does not always run a public faucet. The monitor still talks to the
//! faucet for its faucet checks, which is what [`FaucetClient`] is for.

use std::num::NonZeroU64;
use std::time::Duration;

use anyhow::{Context, Result};
use miden_node_tracing::info;
use miden_node_utils::usdcx_p2id::UsdcxP2Id;
use miden_protocol::account::AccountId;
use miden_protocol::asset::AssetId;
use miden_protocol::note::Note;
use miden_protocol::utils::serde::Deserializable;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::LOG_TARGET;
use crate::config::MonitorConfig;
use crate::faucet::{
    GetMetadataResponse,
    GetTokensResponse,
    fetch_faucet_metadata,
    request_tokens,
};

/// Upper bound on the fee formula's cycle multiplier: the kernel charges `verification_base_fee *
/// (ilog2(total_cycles) + 1)` with cycles capped at `2^29`.
const MAX_FEE_VERIFICATION_CYCLES: u64 = 30;

/// Divisor of the wallet funding amount that gives the wallet's top-up threshold.
///
/// A tenth keeps a reserve for funding service outages while bounding the wallet's balance, and so
/// what a restart abandons, to about 1.1 times the funding amount.
const WALLET_TOPUP_THRESHOLD_DIVISOR: u64 = 10;

/// Transactions the counter is funded for at deployment. It only pays its own creation fee from
/// this; later network transactions are paid by the sponsorship note each increment attaches. Kept
/// small: the counter allowlists P2ID at zero price, so third parties can drain this buffer with
/// dust notes, but increments keep working since sponsorships are collected before fees.
const COUNTER_FUNDING_TXS: u64 = 2;

/// Hard upper bound on one transaction's fee under the given base fee.
pub fn max_fee_per_transaction(verification_base_fee: u32) -> u64 {
    u64::from(verification_base_fee) * MAX_FEE_VERIFICATION_CYCLES
}

/// Cost of one increment to the wallet: its own fee plus the sponsorship note.
pub fn wallet_budget_per_increment(verification_base_fee: u32) -> u64 {
    max_fee_per_transaction(verification_base_fee) * 2
}

/// Wallet balance below which a top-up of `wallet_funding_amount` is requested.
pub fn wallet_topup_threshold(wallet_funding_amount: NonZeroU64) -> u64 {
    wallet_funding_amount.get().div_ceil(WALLET_TOPUP_THRESHOLD_DIVISOR)
}

/// Amount requested when funding the counter account at deployment.
pub fn counter_funding_amount(verification_base_fee: u32) -> u64 {
    max_fee_per_transaction(verification_base_fee) * COUNTER_FUNDING_TXS
}

/// HTTP client for the chain's faucet service, used by the monitor's faucet checks.
///
/// Wraps the token-request flow, which is a proof-of-work challenge plus `/get_tokens`, and the
/// metadata endpoint. The monitor does not pay fees from the faucet.
#[derive(Clone, Debug)]
pub struct FaucetClient {
    faucet_url: Url,
    client: Client,
    /// Wall-clock cap on solving a single faucet proof-of-work challenge.
    solve_timeout: Duration,
}

impl FaucetClient {
    pub fn new(faucet_url: Url, request_timeout: Duration) -> Self {
        let client = Client::builder()
            .timeout(request_timeout)
            .build()
            .expect("Failed to create HTTP client with timeout");
        Self {
            faucet_url,
            client,
            solve_timeout: request_timeout,
        }
    }

    /// Returns the faucet's base URL.
    pub fn url(&self) -> &Url {
        &self.faucet_url
    }

    /// Requests `amount` base units for `account_id`, solving the faucet's proof-of-work challenge.
    /// Does not wait for the minted note to commit.
    pub(crate) async fn request_tokens(
        &self,
        account_id: &str,
        amount: u64,
    ) -> Result<GetTokensResponse> {
        request_tokens(&self.client, &self.faucet_url, account_id, amount, self.solve_timeout).await
    }

    /// Fetches the faucet's metadata.
    pub(crate) async fn metadata(&self) -> Result<GetMetadataResponse> {
        fetch_faucet_metadata(&self.client, &self.faucet_url).await
    }
}

/// Builds the funding service client when its URL is configured.
pub fn funding_client_from_config(config: &MonitorConfig) -> Option<FundingClient> {
    let url = config.funding_service_url.clone()?;

    Some(FundingClient::new(url, config.funding_request_timeout))
}

// FUNDING CLIENT
// ================================================================================================

/// The path of the funding service's funding endpoint.
const REQUEST_FUNDS_PATH: &str = "request-funds";

/// The body of a funding request.
#[derive(Debug, Deserialize, Serialize)]
struct RequestFundsRequest {
    /// The account which the note targets, in hexadecimal.
    account_id: String,
    /// The amount of the native asset, in base units.
    amount: u64,
}

/// The body of a successful funding response.
#[derive(Debug, Deserialize, Serialize)]
struct RequestFundsResponse {
    /// The serialized note, in hexadecimal.
    note: String,
}

/// Requests the chain's fee asset from the funding service over its JSON HTTP API.
#[derive(Clone, Debug)]
pub struct FundingClient {
    service_url: Url,
    client: Client,
}

impl FundingClient {
    pub fn new(service_url: Url, request_timeout: Duration) -> Self {
        let client = Client::builder()
            .timeout(request_timeout)
            .build()
            .expect("Failed to create HTTP client with timeout");

        Self { service_url, client }
    }

    /// Requests `amount` base units for `account_id` and returns the note the service creates.
    ///
    /// The service answers before it submits the transaction which creates the note, so the note is
    /// not on chain yet. The caller consumes it as an unauthenticated input note.
    async fn request_funds(&self, account_id: AccountId, amount: u64) -> Result<Note> {
        let url = self
            .service_url
            .join(REQUEST_FUNDS_PATH)
            .context("failed to build the funding service URL")?;

        let response = self
            .client
            .post(url)
            .json(&RequestFundsRequest { account_id: account_id.to_hex(), amount })
            .send()
            .await
            .context("failed to reach the funding service")?
            .error_for_status()
            .context("the funding service rejected the request")?
            .json::<RequestFundsResponse>()
            .await
            .context("failed to read the response of the funding service")?;

        // The response carries the note in full, so the monitor does not look it up at the node.
        let bytes = hex::decode(&response.note)
            .context("the funding service returned a note which is not hexadecimal")?;

        Note::read_from_bytes(&bytes)
            .context("failed to deserialize the note of the funding service")
    }
}

/// Funds monitor accounts with the chain's fee asset.
///
/// Binds the funding service client to the chain's fee asset, so callers fund an account from just
/// an ID and an amount. The fee faucet comes from the protocol configuration which the node serves.
pub struct FeeFunder {
    client: FundingClient,
    fee_faucet_id: AccountId,
}

impl FeeFunder {
    pub fn new(client: FundingClient, fee_faucet_id: AccountId) -> Self {
        Self { client, fee_faucet_id }
    }

    /// Requests `amount` base units for `account_id` and returns the P2ID note the service creates.
    pub async fn fund(&mut self, account_id: AccountId, amount: u64) -> Result<UsdcxP2Id> {
        let note = self.client.request_funds(account_id, amount).await?;

        let note = UsdcxP2Id::from_note(note, AssetId::new_fungible(self.fee_faucet_id)).context(
            "the funding service must return a public P2ID note holding only the chain's fee asset",
        )?;
        anyhow::ensure!(
            note.target() == account_id,
            "the funding note targets {} instead of {account_id}",
            note.target()
        );
        anyhow::ensure!(
            note.amount() == amount,
            "the funding note holds {} base units instead of {amount}",
            note.amount()
        );

        info!(
            target: LOG_TARGET,
            "Received fee tokens from the funding service",
            account.id = account_id,
            note.id = note.note().id(),
            asset.amount = amount
        );

        Ok(note)
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use axum::routing::post;
    use axum::{Json, Router};
    use clap::Parser;
    use miden_protocol::Word;
    use miden_protocol::asset::FungibleAsset;
    use miden_protocol::note::NoteType;
    use miden_protocol::testing::account_id::{
        ACCOUNT_ID_PRIVATE_SENDER,
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
        ACCOUNT_ID_SENDER,
    };
    use miden_protocol::utils::serde::Serializable;
    use miden_standards::note::P2idNote;
    use tokio::sync::watch;

    use super::*;

    /// Parses a monitor configuration which holds the given arguments and nothing else of interest.
    fn config_with(arguments: &[&str]) -> MonitorConfig {
        let mut command = vec!["miden-network-monitor", "--rpc-url", "http://rpc.invalid"];
        command.extend_from_slice(arguments);
        MonitorConfig::parse_from(command)
    }

    /// An empty wallet must request funds, and a wallet that just received a top-up must not
    /// request another one, whatever amount the operator configures.
    #[test]
    fn one_topup_clears_the_threshold() {
        for amount in [1, 2, 3, 9, 11, 1_000, 1_000_000, u64::MAX] {
            let threshold =
                wallet_topup_threshold(NonZeroU64::new(amount).expect("amounts are non-zero"));
            assert!(threshold > 0, "an empty wallet must request funds for amount {amount}");
            assert!(
                amount >= threshold,
                "a topped-up empty wallet must clear the threshold for amount {amount}"
            );
        }
    }

    /// Fees come from the funding service only, so a configured faucet must not produce a funding
    /// client.
    #[tokio::test]
    async fn only_the_funding_service_url_provides_fee_funding() {
        let faucet_url = Url::parse("http://faucet.invalid").expect("static URL is valid");
        let service_url = Url::parse("http://funding.invalid").expect("static URL is valid");

        let service = config_with(&["--funding-service-url", service_url.as_str()]);
        assert!(funding_client_from_config(&service).is_some());

        let faucet_only = config_with(&["--faucet-url", faucet_url.as_str()]);
        assert!(
            funding_client_from_config(&faucet_only).is_none(),
            "the faucet must not be used as a source of fees"
        );

        let neither = config_with(&[]);
        assert!(
            funding_client_from_config(&neither).is_none(),
            "without the funding service the chain must not charge fees"
        );
    }

    /// The response must match the requested recipient, amount, and note format.
    #[tokio::test]
    async fn funding_responses_are_validated_before_use() {
        let fee_faucet_id = FungibleAsset::mock_issuer();
        let target: AccountId = ACCOUNT_ID_SENDER.try_into().unwrap();
        let other_target = ACCOUNT_ID_PRIVATE_SENDER.try_into().unwrap();
        let other_faucet = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1.try_into().unwrap();
        let note = |target, faucet, amount, note_type| -> Note {
            P2idNote::builder()
                .sender(faucet)
                .target(target)
                .serial_number(Word::from([7u32; 4]))
                .note_type(note_type)
                .asset(FungibleAsset::new(faucet, amount).unwrap())
                .build()
                .unwrap()
                .into()
        };
        let valid = note(target, fee_faucet_id, 100, NoteType::Public);
        let (tx, rx) = watch::channel(hex::encode(valid.to_bytes()));
        let app = Router::new().route(
            "/request-funds",
            post(move || {
                let note = rx.borrow().clone();
                async move { Json(RequestFundsResponse { note }) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let mut funder =
            FeeFunder::new(FundingClient::new(url, Duration::from_secs(5)), fee_faucet_id);

        let received = funder.fund(target, 100).await.unwrap();
        assert_eq!(received.target(), target);
        assert_eq!(received.amount(), 100);
        assert_eq!(received.note(), &valid);
        for (note, expected_error) in [
            (note(other_target, fee_faucet_id, 100, NoteType::Public), "targets"),
            (note(target, fee_faucet_id, 0, NoteType::Public), "base units"),
            (note(target, fee_faucet_id, 99, NoteType::Public), "base units"),
            (note(target, fee_faucet_id, 101, NoteType::Public), "base units"),
            (note(target, other_faucet, 100, NoteType::Public), "public P2ID"),
            (note(target, fee_faucet_id, 100, NoteType::Private), "public P2ID"),
        ] {
            tx.send_replace(hex::encode(note.to_bytes()));
            let error = funder.fund(target, 100).await.expect_err("invalid funding response");
            assert!(error.to_string().contains(expected_error), "unexpected error: {error:#}");
        }
        server.abort();
    }
}
