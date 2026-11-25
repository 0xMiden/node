use std::time::Duration;

use anyhow::Context;
use miden_node_store::allowlist::InvitationCode;
use miden_protocol::account::AccountId;
use reqwest::{Client, RequestBuilder, Response, header};
use url::Url;

pub(crate) struct AdminClient {
    http: Client,
    url: Url,
}

impl AdminClient {
    pub(crate) fn new(url: Url) -> anyhow::Result<Self> {
        let http = Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(180))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("failed to create admin client")?;
        Ok(Self { http, url })
    }

    pub(crate) async fn create_invitation(&self, code: &str) -> anyhow::Result<()> {
        let invitation = InvitationCode::new(code).context("invalid invitation code")?;
        let url =
            self.endpoint(&["admin", "allowlist", "invitations", &invitation.to_hex_digest()])?;
        self.send(self.http.put(url).json(&serde_json::json!({}))).await.map(|_| ())
    }

    pub(crate) async fn allowlist_account(&self, account_id: AccountId) -> anyhow::Result<()> {
        let url = self.endpoint(&["admin", "allowlist", "accounts", &account_id.to_hex()])?;
        self.send(self.http.put(url)).await.map(|_| ())
    }

    pub(crate) async fn validator_config_status(&self) -> anyhow::Result<serde_json::Value> {
        let url = self.endpoint(&["admin", "v1", "validator-config"])?;
        self.send(self.http.get(url))
            .await?
            .json()
            .await
            .context("invalid validator quorum status")
    }

    pub(crate) async fn register_validator_config(
        &self,
        change: Vec<u8>,
        activation_height: u32,
    ) -> anyhow::Result<()> {
        let mut url = self.endpoint(&["admin", "v1", "validator-config", "pending"])?;
        url.query_pairs_mut()
            .append_pair("activation_height", &activation_height.to_string());
        self.send(self.http.put(url).header(header::CONTENT_TYPE, "application/json").body(change))
            .await
            .map(|_| ())
    }

    pub(crate) async fn cancel_validator_config(
        &self,
        change: Vec<u8>,
        activation_height: u32,
    ) -> anyhow::Result<()> {
        let mut url = self.endpoint(&["admin", "v1", "validator-config", "pending"])?;
        url.query_pairs_mut()
            .append_pair("activation_height", &activation_height.to_string());
        self.send(
            self.http
                .delete(url)
                .header(header::CONTENT_TYPE, "application/json")
                .body(change),
        )
        .await
        .map(|_| ())
    }

    fn endpoint(&self, segments: &[&str]) -> anyhow::Result<Url> {
        let mut url = self.url.clone();
        url.path_segments_mut()
            .map_err(|()| anyhow::anyhow!("admin URL must be a base URL"))?
            .pop_if_empty()
            .extend(segments);
        Ok(url)
    }

    async fn send(&self, request: RequestBuilder) -> anyhow::Result<Response> {
        let response = request.send().await.context("admin request failed")?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.context("failed to read admin error response")?;
            anyhow::bail!("admin request failed ({status}): {body}");
        }
        Ok(response)
    }
}
