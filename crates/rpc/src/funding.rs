use std::num::NonZeroU64;
use std::time::Duration;

use anyhow::Context;
use miden_node_tracing::miden_instrument;
use miden_protocol::account::AccountId;
use reqwest::Client;
use serde::Serialize;
use url::Url;

use crate::COMPONENT;

/// Requests public P2ID notes from the funding service.
#[derive(Clone)]
pub struct FundingClient {
    http: Client,
    url: Url,
    amount: NonZeroU64,
}

impl FundingClient {
    pub fn new(mut url: Url, amount: NonZeroU64) -> anyhow::Result<Self> {
        anyhow::ensure!(
            matches!(url.scheme(), "http" | "https") && url.host_str().is_some(),
            "funding service URL must use HTTP or HTTPS"
        );
        anyhow::ensure!(
            url.query().is_none() && url.fragment().is_none(),
            "funding service URL must not contain a query or fragment"
        );
        url.path_segments_mut()
            .map_err(|()| anyhow::anyhow!("funding service URL must be a base URL"))?
            .pop_if_empty()
            .push("request-funds");
        let http = Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(120))
            .build()
            .context("failed to create funding service client")?;
        Ok(Self { http, url, amount })
    }

    /// Requests the configured amount and waits for the funding note to commit. This method does
    /// not retry failed requests.
    #[miden_instrument(
        target = COMPONENT,
        name = "account.funding",
        fields(account.id = account_id, asset.amount = self.amount.get()),
        err,
    )]
    pub async fn fund(&self, account_id: AccountId) -> anyhow::Result<()> {
        self.http
            .post(self.url.clone())
            .json(&FundingRequest {
                account_id: account_id.to_hex(),
                amount: self.amount.get(),
            })
            .send()
            .await
            .context("failed to send account funding request")?
            .error_for_status()
            .context("funding service rejected account funding request")?
            // Clients retrieve the public note through the account's note tag.
            .bytes()
            .await
            .context("failed to read account funding response")?;
        Ok(())
    }
}

#[derive(Serialize)]
struct FundingRequest {
    account_id: String,
    amount: u64,
}
