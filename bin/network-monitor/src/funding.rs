//! Fee funding for the monitor's accounts.
//!
//! Fees are withdrawn from the executing account's vault, so on a fee-charging chain the
//! monitor's fresh accounts need the fee asset before they can transact. This module requests a
//! public P2ID note from the faucet, waits for it to commit, and returns it for consumption as an
//! unauthenticated input note.
// TODO(#2450): Mainnet has no faucet service; funding there needs a manual note-import path.

use std::time::Duration;

use anyhow::{Context, Result};
use miden_node_proto::clients::RpcClient;
use miden_node_proto::generated::note::NoteIdList;
use miden_node_tracing::{info, warn};
use miden_protocol::account::AccountId;
use miden_protocol::asset::Asset;
use miden_protocol::note::{Note, NoteId};
use reqwest::Client;
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

/// Increments one wallet funding request should cover, roughly a week at the default cadence.
const WALLET_FUNDING_INCREMENTS: u64 = 20_000;

/// Remaining-increment level at which the wallet requests a top-up from the faucet.
const WALLET_TOPUP_THRESHOLD_INCREMENTS: u64 = 1_000;

/// Largest amount requested per faucet call, matching the faucet's default
/// `--max-claimable-amount`. Larger requests are rejected with an HTTP 400.
const MAX_FAUCET_REQUEST_AMOUNT: u64 = 1_000_000_000;

/// Transactions the counter is funded for at deployment. It only pays its own creation fee from
/// this; later network transactions are paid by the sponsorship note each increment attaches. Kept
/// small: the counter allowlists P2ID at zero price, so third parties can drain this buffer with
/// dust notes, but increments keep working since sponsorships are collected before fees.
const COUNTER_FUNDING_TXS: u64 = 2;

/// Attempts to find a freshly-minted note before giving up.
const NOTE_LOOKUP_ATTEMPTS: usize = 30;

/// Delay between note lookup attempts.
const NOTE_LOOKUP_DELAY: Duration = Duration::from_secs(2);

/// Hard upper bound on one transaction's fee under the given base fee.
pub fn max_fee_per_transaction(verification_base_fee: u32) -> u64 {
    u64::from(verification_base_fee) * MAX_FEE_VERIFICATION_CYCLES
}

/// Cost of one increment to the wallet: its own fee plus the sponsorship note.
pub fn wallet_budget_per_increment(verification_base_fee: u32) -> u64 {
    max_fee_per_transaction(verification_base_fee) * 2
}

/// Amount requested from the faucet when funding or topping up the wallet.
pub fn wallet_funding_amount(verification_base_fee: u32) -> u64 {
    (wallet_budget_per_increment(verification_base_fee) * WALLET_FUNDING_INCREMENTS)
        .min(MAX_FAUCET_REQUEST_AMOUNT)
}

/// Wallet balance below which a top-up is requested. Clamped to half the request cap so a capped
/// funding request still clears the threshold.
pub fn wallet_topup_threshold(verification_base_fee: u32) -> u64 {
    (wallet_budget_per_increment(verification_base_fee) * WALLET_TOPUP_THRESHOLD_INCREMENTS)
        .min(MAX_FAUCET_REQUEST_AMOUNT / 2)
}

/// Amount requested from the faucet when funding the counter account at deployment.
pub fn counter_funding_amount(verification_base_fee: u32) -> u64 {
    (max_fee_per_transaction(verification_base_fee) * COUNTER_FUNDING_TXS)
        .min(MAX_FAUCET_REQUEST_AMOUNT)
}

/// HTTP client for the chain's faucet service.
///
/// Wraps the token-request flow (proof-of-work challenge plus `/get_tokens`) and the
/// monitor-specific funding flow built on top of it.
#[derive(Clone, Debug)]
pub struct FaucetClient {
    faucet_url: Url,
    client: Client,
    /// Wall-clock cap on solving a single faucet proof-of-work challenge.
    solve_timeout: Duration,
}

impl FaucetClient {
    /// Builds the client when a faucet URL is configured.
    pub fn from_config(config: &MonitorConfig) -> Option<Self> {
        config.faucet_url.clone().map(|url| Self::new(url, config.request_timeout))
    }

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

/// Funds monitor accounts with the chain's fee asset.
///
/// Binds a [`FaucetClient`] to the RPC client used to await note commitment and to the chain's
/// fee faucet ID, so callers fund an account from just an ID and an amount. Built where the
/// genesis header is known, since the fee faucet ID comes from the genesis fee parameters.
pub struct FeeFunder {
    faucet: FaucetClient,
    rpc_client: RpcClient,
    fee_faucet_id: AccountId,
}

impl FeeFunder {
    pub fn new(faucet: FaucetClient, rpc_client: RpcClient, fee_faucet_id: AccountId) -> Self {
        Self { faucet, rpc_client, fee_faucet_id }
    }

    /// Requests `amount` base units for `account_id` and waits for the resulting public P2ID note
    /// to commit. The note's asset is checked against the fee faucet ID so a faucet minting the
    /// wrong token fails here instead of as opaque fee aborts later.
    pub async fn fund(&mut self, account_id: AccountId, amount: u64) -> Result<Note> {
        let tokens = self
            .faucet
            .request_tokens(&account_id.to_string(), amount)
            .await
            .context("faucet token request failed")?;

        let note_id = NoteId::try_from_hex(&tokens.note_id)
            .with_context(|| format!("faucet returned an invalid note id: {}", tokens.note_id))?;

        info!(
            target: LOG_TARGET,
            "Requested fee tokens from the faucet",
            account.id = account_id,
            note.id = note_id,
            asset.amount = amount
        );

        let note = await_committed_note(&mut self.rpc_client, note_id).await?;
        ensure_note_carries_fee_asset(&note, self.fee_faucet_id).with_context(|| {
            format!(
                "the faucet at {} did not mint the chain's fee asset: is --faucet-url pointing \
                 at the chain's native faucet?",
                self.faucet.url()
            )
        })?;
        Ok(note)
    }
}

/// Checks that the note holds a non-zero amount of the fee faucet's fungible asset.
fn ensure_note_carries_fee_asset(note: &Note, fee_faucet_id: AccountId) -> Result<()> {
    let funded = note.assets().iter().any(|asset| {
        asset.as_fungible().is_some_and(|asset| {
            asset.faucet_id() == fee_faucet_id && asset.amount().as_u64() > 0
        })
    });
    anyhow::ensure!(
        funded,
        "note {} does not hold the fee asset issued by faucet {fee_faucet_id}",
        note.id().to_hex()
    );
    Ok(())
}

/// Polls the node until the given public note is committed and returns it in full.
async fn await_committed_note(rpc_client: &mut RpcClient, note_id: NoteId) -> Result<Note> {
    for attempt in 1..=NOTE_LOOKUP_ATTEMPTS {
        if attempt > 1 {
            tokio::time::sleep(NOTE_LOOKUP_DELAY).await;
        }

        match fetch_note(rpc_client, note_id).await {
            Ok(Some(note)) => return Ok(note),
            Ok(None) => {},
            Err(err) => warn!(
                &err,
                target: LOG_TARGET,
                "Failed to look up the funding note; retrying",
                retry.attempt = attempt
            ),
        }
    }

    anyhow::bail!(
        "funding note {} was not committed within {} attempts",
        note_id.to_hex(),
        NOTE_LOOKUP_ATTEMPTS
    )
}

/// Fetches one public note by ID; `Ok(None)` while the note is not committed yet.
async fn fetch_note(rpc_client: &mut RpcClient, note_id: NoteId) -> Result<Option<Note>> {
    let response = rpc_client
        .get_notes_by_id(NoteIdList { ids: vec![note_id.as_word().into()] })
        .await
        .context("failed to fetch the funding note from RPC")?
        .into_inner();

    let Some(committed) = response.notes.into_iter().next() else {
        return Ok(None);
    };

    let note = committed
        .note
        .context("committed note response is missing the note")?
        .try_into()
        .context("failed to convert the funding note")?;

    Ok(Some(note))
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::Word;
    use miden_protocol::asset::FungibleAsset;
    use miden_protocol::note::NoteType;
    use miden_standards::note::P2idNote;

    use super::*;
    use crate::deploy::wallet::create_wallet_account;

    /// Requested amounts must stay within the faucet's claim limit, and a capped request must still
    /// clear the top-up threshold.
    #[test]
    fn funding_amounts_respect_the_faucet_claim_limit() {
        for base_fee in [1, 500, 834, 10_000, u32::MAX] {
            assert!(wallet_funding_amount(base_fee) <= MAX_FAUCET_REQUEST_AMOUNT);
            assert!(counter_funding_amount(base_fee) <= MAX_FAUCET_REQUEST_AMOUNT);
            assert!(
                wallet_funding_amount(base_fee) >= 2 * wallet_topup_threshold(base_fee),
                "a single funding request must cover at least two thresholds at base fee \
                 {base_fee}"
            );
        }

        // Small base fees stay on the uncapped formula.
        assert_eq!(
            wallet_funding_amount(1),
            wallet_budget_per_increment(1) * WALLET_FUNDING_INCREMENTS
        );
        // Large base fees hit the cap instead of producing a rejected request.
        assert_eq!(wallet_funding_amount(10_000), MAX_FAUCET_REQUEST_AMOUNT);
    }

    /// A faucet minting the wrong token must fail at claim time, not as later fee aborts.
    #[test]
    fn funding_note_must_carry_the_fee_asset() {
        let fee_faucet_id = FungibleAsset::mock_issuer();
        let (wallet, _secret_key) = create_wallet_account().expect("wallet account should build");
        let note: Note = P2idNote::builder()
            .sender(fee_faucet_id)
            .target(wallet.id())
            .serial_number(Word::from([7u32; 4]))
            .note_type(NoteType::Public)
            .asset(FungibleAsset::new(fee_faucet_id, 100).expect("valid asset"))
            .build()
            .expect("the note should build")
            .into();

        ensure_note_carries_fee_asset(&note, fee_faucet_id)
            .expect("a note carrying the fee asset must be accepted");
        // Any other issuer id must be rejected; the wallet id stands in for a wrong faucet.
        ensure_note_carries_fee_asset(&note, wallet.id())
            .expect_err("a note without the fee asset must be rejected");
    }
}
